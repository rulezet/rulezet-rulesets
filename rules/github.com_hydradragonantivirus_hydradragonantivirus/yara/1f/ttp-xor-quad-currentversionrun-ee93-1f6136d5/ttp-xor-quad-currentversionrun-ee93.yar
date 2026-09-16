rule TTP_XOR_QUAD_CurrentVersionRun_ee93 {
  strings:
    $key_ee93 = { bd fc [2] 99 f2 [2] b2 de [2] 9c fc [2] 88 e7 [2] 87 fd [2] 99 e0 [2] 9b e1 [2] 80 e7 [2] 9c e0 [2] 80 cf }

  condition:
    any of them
}