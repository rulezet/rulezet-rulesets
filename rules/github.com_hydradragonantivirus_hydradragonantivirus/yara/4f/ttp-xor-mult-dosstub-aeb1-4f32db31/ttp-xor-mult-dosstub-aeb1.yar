rule TTP_XOR_MULT_DOSStub_aeb1 {
  strings:
    $key_aeb1 = { fa d9 [2] 8e c1 [2] c9 c3 [2] 8e d2 [2] c0 de [2] cc d4 [2] db df [2] c0 91 [2] fd }

  condition:
    any of them
}