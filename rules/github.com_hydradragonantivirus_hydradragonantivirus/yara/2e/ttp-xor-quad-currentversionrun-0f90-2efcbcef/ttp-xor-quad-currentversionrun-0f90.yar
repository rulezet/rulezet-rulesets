rule TTP_XOR_QUAD_CurrentVersionRun_0f90 {
  strings:
    $key_0f90 = { 5c ff [2] 78 f1 [2] 53 dd [2] 7d ff [2] 69 e4 [2] 66 fe [2] 78 e3 [2] 7a e2 [2] 61 e4 [2] 7d e3 [2] 61 cc }

  condition:
    any of them
}