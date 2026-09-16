rule TTP_XOR_QUAD_CurrentVersionRun_00d7 {
  strings:
    $key_00d7 = { 53 b8 [2] 77 b6 [2] 5c 9a [2] 72 b8 [2] 66 a3 [2] 69 b9 [2] 77 a4 [2] 75 a5 [2] 6e a3 [2] 72 a4 [2] 6e 8b }

  condition:
    any of them
}