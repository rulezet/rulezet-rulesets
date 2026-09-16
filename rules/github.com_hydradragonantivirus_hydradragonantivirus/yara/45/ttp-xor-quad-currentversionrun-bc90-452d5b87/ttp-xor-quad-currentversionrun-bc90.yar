rule TTP_XOR_QUAD_CurrentVersionRun_bc90 {
  strings:
    $key_bc90 = { ef ff [2] cb f1 [2] e0 dd [2] ce ff [2] da e4 [2] d5 fe [2] cb e3 [2] c9 e2 [2] d2 e4 [2] ce e3 [2] d2 cc }

  condition:
    any of them
}