rule TTP_XOR_MULT_DOSStub_bfd7 {
  strings:
    $key_bfd7 = { eb bf [2] 9f a7 [2] d8 a5 [2] 9f b4 [2] d1 b8 [2] dd b2 [2] ca b9 [2] d1 f7 [2] ec }

  condition:
    any of them
}