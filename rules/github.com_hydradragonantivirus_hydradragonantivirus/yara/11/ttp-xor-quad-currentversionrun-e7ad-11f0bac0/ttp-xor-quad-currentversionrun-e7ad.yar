rule TTP_XOR_QUAD_CurrentVersionRun_e7ad {
  strings:
    $key_e7ad = { b4 c2 [2] 90 cc [2] bb e0 [2] 95 c2 [2] 81 d9 [2] 8e c3 [2] 90 de [2] 92 df [2] 89 d9 [2] 95 de [2] 89 f1 }

  condition:
    any of them
}