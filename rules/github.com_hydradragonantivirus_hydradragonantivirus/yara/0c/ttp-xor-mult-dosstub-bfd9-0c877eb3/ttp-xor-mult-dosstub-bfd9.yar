rule TTP_XOR_MULT_DOSStub_bfd9 {
  strings:
    $key_bfd9 = { eb b1 [2] 9f a9 [2] d8 ab [2] 9f ba [2] d1 b6 [2] dd bc [2] ca b7 [2] d1 f9 [2] ec }

  condition:
    any of them
}