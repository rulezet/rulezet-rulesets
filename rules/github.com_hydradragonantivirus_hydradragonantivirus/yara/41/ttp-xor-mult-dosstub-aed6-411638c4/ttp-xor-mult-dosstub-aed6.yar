rule TTP_XOR_MULT_DOSStub_aed6 {
  strings:
    $key_aed6 = { fa be [2] 8e a6 [2] c9 a4 [2] 8e b5 [2] c0 b9 [2] cc b3 [2] db b8 [2] c0 f6 [2] fd }

  condition:
    any of them
}