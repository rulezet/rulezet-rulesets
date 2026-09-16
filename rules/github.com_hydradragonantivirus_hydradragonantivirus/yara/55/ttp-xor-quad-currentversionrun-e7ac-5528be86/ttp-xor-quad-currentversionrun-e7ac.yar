rule TTP_XOR_QUAD_CurrentVersionRun_e7ac {
  strings:
    $key_e7ac = { b4 c3 [2] 90 cd [2] bb e1 [2] 95 c3 [2] 81 d8 [2] 8e c2 [2] 90 df [2] 92 de [2] 89 d8 [2] 95 df [2] 89 f0 }

  condition:
    any of them
}