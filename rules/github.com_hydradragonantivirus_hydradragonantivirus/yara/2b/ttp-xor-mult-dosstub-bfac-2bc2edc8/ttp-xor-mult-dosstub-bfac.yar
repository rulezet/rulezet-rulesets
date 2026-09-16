rule TTP_XOR_MULT_DOSStub_bfac {
  strings:
    $key_bfac = { eb c4 [2] 9f dc [2] d8 de [2] 9f cf [2] d1 c3 [2] dd c9 [2] ca c2 [2] d1 8c [2] ec }

  condition:
    any of them
}