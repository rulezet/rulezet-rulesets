rule TTP_XOR_MULT_DOSStub_b9d1 {
  strings:
    $key_b9d1 = { ed b9 [2] 99 a1 [2] de a3 [2] 99 b2 [2] d7 be [2] db b4 [2] cc bf [2] d7 f1 [2] ea }

  condition:
    any of them
}