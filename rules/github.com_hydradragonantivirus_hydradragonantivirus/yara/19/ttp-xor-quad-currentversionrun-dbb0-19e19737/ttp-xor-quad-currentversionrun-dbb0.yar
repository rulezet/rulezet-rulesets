rule TTP_XOR_QUAD_CurrentVersionRun_dbb0 {
  strings:
    $key_dbb0 = { 88 df [2] ac d1 [2] 87 fd [2] a9 df [2] bd c4 [2] b2 de [2] ac c3 [2] ae c2 [2] b5 c4 [2] a9 c3 [2] b5 ec }

  condition:
    any of them
}