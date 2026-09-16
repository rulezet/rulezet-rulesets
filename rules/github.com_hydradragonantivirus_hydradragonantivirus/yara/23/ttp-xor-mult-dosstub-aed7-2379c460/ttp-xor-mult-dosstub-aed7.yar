rule TTP_XOR_MULT_DOSStub_aed7 {
  strings:
    $key_aed7 = { fa bf [2] 8e a7 [2] c9 a5 [2] 8e b4 [2] c0 b8 [2] cc b2 [2] db b9 [2] c0 f7 [2] fd }

  condition:
    any of them
}