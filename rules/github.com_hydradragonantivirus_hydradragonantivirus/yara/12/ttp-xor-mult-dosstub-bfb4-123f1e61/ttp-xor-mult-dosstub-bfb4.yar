rule TTP_XOR_MULT_DOSStub_bfb4 {
  strings:
    $key_bfb4 = { eb dc [2] 9f c4 [2] d8 c6 [2] 9f d7 [2] d1 db [2] dd d1 [2] ca da [2] d1 94 [2] ec }

  condition:
    any of them
}