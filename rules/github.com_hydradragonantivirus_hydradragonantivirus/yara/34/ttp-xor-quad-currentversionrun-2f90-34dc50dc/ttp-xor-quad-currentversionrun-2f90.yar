rule TTP_XOR_QUAD_CurrentVersionRun_2f90 {
  strings:
    $key_2f90 = { 7c ff [2] 58 f1 [2] 73 dd [2] 5d ff [2] 49 e4 [2] 46 fe [2] 58 e3 [2] 5a e2 [2] 41 e4 [2] 5d e3 [2] 41 cc }

  condition:
    any of them
}