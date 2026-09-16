rule TTP_XOR_QUAD_CurrentVersionRun_cfb0 {
  strings:
    $key_cfb0 = { 9c df [2] b8 d1 [2] 93 fd [2] bd df [2] a9 c4 [2] a6 de [2] b8 c3 [2] ba c2 [2] a1 c4 [2] bd c3 [2] a1 ec }

  condition:
    any of them
}