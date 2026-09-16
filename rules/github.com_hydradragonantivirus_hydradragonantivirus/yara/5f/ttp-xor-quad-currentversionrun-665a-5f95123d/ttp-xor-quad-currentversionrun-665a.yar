rule TTP_XOR_QUAD_CurrentVersionRun_665a {
  strings:
    $key_665a = { 35 35 [2] 11 3b [2] 3a 17 [2] 14 35 [2] 00 2e [2] 0f 34 [2] 11 29 [2] 13 28 [2] 08 2e [2] 14 29 [2] 08 06 }

  condition:
    any of them
}