rule TTP_XOR_QUAD_CurrentVersionRun_b0f7 {
  strings:
    $key_b0f7 = { e3 98 [2] c7 96 [2] ec ba [2] c2 98 [2] d6 83 [2] d9 99 [2] c7 84 [2] c5 85 [2] de 83 [2] c2 84 [2] de ab }

  condition:
    any of them
}