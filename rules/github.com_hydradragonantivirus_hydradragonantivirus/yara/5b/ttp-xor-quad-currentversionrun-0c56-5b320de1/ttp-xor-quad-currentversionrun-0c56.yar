rule TTP_XOR_QUAD_CurrentVersionRun_0c56 {
  strings:
    $key_0c56 = { 5f 39 [2] 7b 37 [2] 50 1b [2] 7e 39 [2] 6a 22 [2] 65 38 [2] 7b 25 [2] 79 24 [2] 62 22 [2] 7e 25 [2] 62 0a }

  condition:
    any of them
}