rule TTP_XOR_MULT_DOSStub_cad1 {
  strings:
    $key_cad1 = { 9e b9 [2] ea a1 [2] ad a3 [2] ea b2 [2] a4 be [2] a8 b4 [2] bf bf [2] a4 f1 [2] 99 }

  condition:
    any of them
}