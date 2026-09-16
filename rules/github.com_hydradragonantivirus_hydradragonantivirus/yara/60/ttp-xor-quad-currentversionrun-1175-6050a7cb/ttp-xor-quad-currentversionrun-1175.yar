rule TTP_XOR_QUAD_CurrentVersionRun_1175 {
  strings:
    $key_1175 = { 42 1a [2] 66 14 [2] 4d 38 [2] 63 1a [2] 77 01 [2] 78 1b [2] 66 06 [2] 64 07 [2] 7f 01 [2] 63 06 [2] 7f 29 }

  condition:
    any of them
}