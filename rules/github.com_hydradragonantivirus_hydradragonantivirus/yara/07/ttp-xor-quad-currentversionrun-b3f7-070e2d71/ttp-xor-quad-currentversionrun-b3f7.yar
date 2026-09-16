rule TTP_XOR_QUAD_CurrentVersionRun_b3f7 {
  strings:
    $key_b3f7 = { e0 98 [2] c4 96 [2] ef ba [2] c1 98 [2] d5 83 [2] da 99 [2] c4 84 [2] c6 85 [2] dd 83 [2] c1 84 [2] dd ab }

  condition:
    any of them
}