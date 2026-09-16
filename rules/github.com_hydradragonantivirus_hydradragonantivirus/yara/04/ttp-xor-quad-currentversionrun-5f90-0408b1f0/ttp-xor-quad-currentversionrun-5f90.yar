rule TTP_XOR_QUAD_CurrentVersionRun_5f90 {
  strings:
    $key_5f90 = { 0c ff [2] 28 f1 [2] 03 dd [2] 2d ff [2] 39 e4 [2] 36 fe [2] 28 e3 [2] 2a e2 [2] 31 e4 [2] 2d e3 [2] 31 cc }

  condition:
    any of them
}