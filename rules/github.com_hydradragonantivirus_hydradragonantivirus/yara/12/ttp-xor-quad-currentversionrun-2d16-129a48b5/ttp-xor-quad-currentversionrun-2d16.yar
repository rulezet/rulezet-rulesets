rule TTP_XOR_QUAD_CurrentVersionRun_2d16 {
  strings:
    $key_2d16 = { 7e 79 [2] 5a 77 [2] 71 5b [2] 5f 79 [2] 4b 62 [2] 44 78 [2] 5a 65 [2] 58 64 [2] 43 62 [2] 5f 65 [2] 43 4a }

  condition:
    any of them
}