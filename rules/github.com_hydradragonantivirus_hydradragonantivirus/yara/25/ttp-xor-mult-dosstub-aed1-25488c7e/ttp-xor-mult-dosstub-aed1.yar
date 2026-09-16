rule TTP_XOR_MULT_DOSStub_aed1 {
  strings:
    $key_aed1 = { fa b9 [2] 8e a1 [2] c9 a3 [2] 8e b2 [2] c0 be [2] cc b4 [2] db bf [2] c0 f1 [2] fd }

  condition:
    any of them
}