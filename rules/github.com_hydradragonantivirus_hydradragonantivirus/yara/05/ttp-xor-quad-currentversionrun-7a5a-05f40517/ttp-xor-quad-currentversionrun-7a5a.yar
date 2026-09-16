rule TTP_XOR_QUAD_CurrentVersionRun_7a5a {
  strings:
    $key_7a5a = { 29 35 [2] 0d 3b [2] 26 17 [2] 08 35 [2] 1c 2e [2] 13 34 [2] 0d 29 [2] 0f 28 [2] 14 2e [2] 08 29 [2] 14 06 }

  condition:
    any of them
}