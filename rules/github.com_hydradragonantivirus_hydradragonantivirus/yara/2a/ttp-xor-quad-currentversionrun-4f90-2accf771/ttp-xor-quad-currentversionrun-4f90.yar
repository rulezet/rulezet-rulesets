rule TTP_XOR_QUAD_CurrentVersionRun_4f90 {
  strings:
    $key_4f90 = { 1c ff [2] 38 f1 [2] 13 dd [2] 3d ff [2] 29 e4 [2] 26 fe [2] 38 e3 [2] 3a e2 [2] 21 e4 [2] 3d e3 [2] 21 cc }

  condition:
    any of them
}