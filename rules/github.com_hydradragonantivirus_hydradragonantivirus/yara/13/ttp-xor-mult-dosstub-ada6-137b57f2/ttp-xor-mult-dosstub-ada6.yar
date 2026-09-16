rule TTP_XOR_MULT_DOSStub_ada6 {
  strings:
    $key_ada6 = { f9 ce [2] 8d d6 [2] ca d4 [2] 8d c5 [2] c3 c9 [2] cf c3 [2] d8 c8 [2] c3 86 [2] fe }

  condition:
    any of them
}