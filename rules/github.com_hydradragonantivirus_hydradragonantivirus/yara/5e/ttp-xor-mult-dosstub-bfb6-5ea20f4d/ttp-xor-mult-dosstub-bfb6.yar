rule TTP_XOR_MULT_DOSStub_bfb6 {
  strings:
    $key_bfb6 = { eb de [2] 9f c6 [2] d8 c4 [2] 9f d5 [2] d1 d9 [2] dd d3 [2] ca d8 [2] d1 96 [2] ec }

  condition:
    any of them
}