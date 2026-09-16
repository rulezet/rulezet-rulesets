rule TTP_XOR_MULT_DOSStub_bfbc {
  strings:
    $key_bfbc = { eb d4 [2] 9f cc [2] d8 ce [2] 9f df [2] d1 d3 [2] dd d9 [2] ca d2 [2] d1 9c [2] ec }

  condition:
    any of them
}