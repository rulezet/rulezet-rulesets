rule TTP_XOR_QUAD_CurrentVersionRun_daf7 {
  strings:
    $key_daf7 = { 89 98 [2] ad 96 [2] 86 ba [2] a8 98 [2] bc 83 [2] b3 99 [2] ad 84 [2] af 85 [2] b4 83 [2] a8 84 [2] b4 ab }

  condition:
    any of them
}