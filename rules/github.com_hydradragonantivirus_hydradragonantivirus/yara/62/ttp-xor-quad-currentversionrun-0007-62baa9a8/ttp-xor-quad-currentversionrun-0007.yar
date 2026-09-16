rule TTP_XOR_QUAD_CurrentVersionRun_0007 {
  strings:
    $key_0007 = { 53 68 [2] 77 66 [2] 5c 4a [2] 72 68 [2] 66 73 [2] 69 69 [2] 77 74 [2] 75 75 [2] 6e 73 [2] 72 74 [2] 6e 5b }

  condition:
    any of them
}