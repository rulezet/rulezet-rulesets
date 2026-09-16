rule TTP_XOR_QUAD_CurrentVersionRun_2a56 {
  strings:
    $key_2a56 = { 79 39 [2] 5d 37 [2] 76 1b [2] 58 39 [2] 4c 22 [2] 43 38 [2] 5d 25 [2] 5f 24 [2] 44 22 [2] 58 25 [2] 44 0a }

  condition:
    any of them
}