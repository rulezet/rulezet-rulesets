rule TTP_XOR_QUAD_CurrentVersionRun_00d6 {
  strings:
    $key_00d6 = { 53 b9 [2] 77 b7 [2] 5c 9b [2] 72 b9 [2] 66 a2 [2] 69 b8 [2] 77 a5 [2] 75 a4 [2] 6e a2 [2] 72 a5 [2] 6e 8a }

  condition:
    any of them
}