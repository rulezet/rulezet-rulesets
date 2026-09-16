rule TTP_XOR_QUAD_CurrentVersionRun_c0b0 {
  strings:
    $key_c0b0 = { 93 df [2] b7 d1 [2] 9c fd [2] b2 df [2] a6 c4 [2] a9 de [2] b7 c3 [2] b5 c2 [2] ae c4 [2] b2 c3 [2] ae ec }

  condition:
    any of them
}