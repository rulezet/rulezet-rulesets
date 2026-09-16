rule TTP_XOR_QUAD_CurrentVersionRun_1107 {
  strings:
    $key_1107 = { 42 68 [2] 66 66 [2] 4d 4a [2] 63 68 [2] 77 73 [2] 78 69 [2] 66 74 [2] 64 75 [2] 7f 73 [2] 63 74 [2] 7f 5b }

  condition:
    any of them
}