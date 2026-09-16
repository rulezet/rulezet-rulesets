rule TTP_XOR_QUAD_CurrentVersionRun_1336 {
  strings:
    $key_1336 = { 40 59 [2] 64 57 [2] 4f 7b [2] 61 59 [2] 75 42 [2] 7a 58 [2] 64 45 [2] 66 44 [2] 7d 42 [2] 61 45 [2] 7d 6a }

  condition:
    any of them
}