rule TTP_XOR_MULT_DOSStub_bfb1 {
  strings:
    $key_bfb1 = { eb d9 [2] 9f c1 [2] d8 c3 [2] 9f d2 [2] d1 de [2] dd d4 [2] ca df [2] d1 91 [2] ec }

  condition:
    any of them
}