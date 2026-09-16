rule TTP_XOR_MULT_DOSStub_aed5 {
  strings:
    $key_aed5 = { fa bd [2] 8e a5 [2] c9 a7 [2] 8e b6 [2] c0 ba [2] cc b0 [2] db bb [2] c0 f5 [2] fd }

  condition:
    any of them
}