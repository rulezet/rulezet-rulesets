rule TTP_XOR_QUAD_CurrentVersionRun_bc93 {
  strings:
    $key_bc93 = { ef fc [2] cb f2 [2] e0 de [2] ce fc [2] da e7 [2] d5 fd [2] cb e0 [2] c9 e1 [2] d2 e7 [2] ce e0 [2] d2 cf }

  condition:
    any of them
}