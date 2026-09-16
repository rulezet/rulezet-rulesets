rule TTP_XOR_QUAD_CurrentVersionRun_7d54 {
  strings:
    $key_7d54 = { 2e 3b [2] 0a 35 [2] 21 19 [2] 0f 3b [2] 1b 20 [2] 14 3a [2] 0a 27 [2] 08 26 [2] 13 20 [2] 0f 27 [2] 13 08 }

  condition:
    any of them
}