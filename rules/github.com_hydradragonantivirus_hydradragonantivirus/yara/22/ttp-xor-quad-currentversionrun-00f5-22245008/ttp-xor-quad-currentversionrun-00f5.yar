rule TTP_XOR_QUAD_CurrentVersionRun_00f5 {
  strings:
    $key_00f5 = { 53 9a [2] 77 94 [2] 5c b8 [2] 72 9a [2] 66 81 [2] 69 9b [2] 77 86 [2] 75 87 [2] 6e 81 [2] 72 86 [2] 6e a9 }

  condition:
    any of them
}