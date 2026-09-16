rule TTP_XOR_QUAD_CurrentVersionRun_daca {
  strings:
    $key_daca = { 89 a5 [2] ad ab [2] 86 87 [2] a8 a5 [2] bc be [2] b3 a4 [2] ad b9 [2] af b8 [2] b4 be [2] a8 b9 [2] b4 96 }

  condition:
    any of them
}