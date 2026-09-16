rule TTP_XOR_QUAD_CurrentVersionRun_0c47 {
  strings:
    $key_0c47 = { 5f 28 [2] 7b 26 [2] 50 0a [2] 7e 28 [2] 6a 33 [2] 65 29 [2] 7b 34 [2] 79 35 [2] 62 33 [2] 7e 34 [2] 62 1b }

  condition:
    any of them
}