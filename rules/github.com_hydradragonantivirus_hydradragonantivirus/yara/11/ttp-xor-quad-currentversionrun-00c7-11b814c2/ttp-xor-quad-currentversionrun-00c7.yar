rule TTP_XOR_QUAD_CurrentVersionRun_00c7 {
  strings:
    $key_00c7 = { 53 a8 [2] 77 a6 [2] 5c 8a [2] 72 a8 [2] 66 b3 [2] 69 a9 [2] 77 b4 [2] 75 b5 [2] 6e b3 [2] 72 b4 [2] 6e 9b }

  condition:
    any of them
}