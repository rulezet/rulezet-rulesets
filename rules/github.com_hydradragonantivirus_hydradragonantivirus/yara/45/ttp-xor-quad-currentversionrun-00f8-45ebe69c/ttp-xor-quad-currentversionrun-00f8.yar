rule TTP_XOR_QUAD_CurrentVersionRun_00f8 {
  strings:
    $key_00f8 = { 53 97 [2] 77 99 [2] 5c b5 [2] 72 97 [2] 66 8c [2] 69 96 [2] 77 8b [2] 75 8a [2] 6e 8c [2] 72 8b [2] 6e a4 }

  condition:
    any of them
}