rule TTP_XOR_QUAD_CurrentVersionRun_8ab1 {
  strings:
    $key_8ab1 = { d9 de [2] fd d0 [2] d6 fc [2] f8 de [2] ec c5 [2] e3 df [2] fd c2 [2] ff c3 [2] e4 c5 [2] f8 c2 [2] e4 ed }

  condition:
    any of them
}