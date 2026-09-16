rule TTP_XOR_QUAD_CurrentVersionRun_2407 {
  strings:
    $key_2407 = { 77 68 [2] 53 66 [2] 78 4a [2] 56 68 [2] 42 73 [2] 4d 69 [2] 53 74 [2] 51 75 [2] 4a 73 [2] 56 74 [2] 4a 5b }

  condition:
    any of them
}