rule TTP_XOR_MULT_DOSStub_bfa6 {
  strings:
    $key_bfa6 = { eb ce [2] 9f d6 [2] d8 d4 [2] 9f c5 [2] d1 c9 [2] dd c3 [2] ca c8 [2] d1 86 [2] ec }

  condition:
    any of them
}