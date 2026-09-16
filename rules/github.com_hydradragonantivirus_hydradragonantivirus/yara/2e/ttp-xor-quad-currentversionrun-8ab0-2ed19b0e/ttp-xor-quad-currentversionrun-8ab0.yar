rule TTP_XOR_QUAD_CurrentVersionRun_8ab0 {
  strings:
    $key_8ab0 = { d9 df [2] fd d1 [2] d6 fd [2] f8 df [2] ec c4 [2] e3 de [2] fd c3 [2] ff c2 [2] e4 c4 [2] f8 c3 [2] e4 ec }

  condition:
    any of them
}