rule TTP_XOR_QUAD_CurrentVersionRun_c2b0 {
  strings:
    $key_c2b0 = { 91 df [2] b5 d1 [2] 9e fd [2] b0 df [2] a4 c4 [2] ab de [2] b5 c3 [2] b7 c2 [2] ac c4 [2] b0 c3 [2] ac ec }

  condition:
    any of them
}