rule TTP_XOR_QUAD_CurrentVersionRun_4316 {
  strings:
    $key_4316 = { 10 79 [2] 34 77 [2] 1f 5b [2] 31 79 [2] 25 62 [2] 2a 78 [2] 34 65 [2] 36 64 [2] 2d 62 [2] 31 65 [2] 2d 4a }

  condition:
    any of them
}