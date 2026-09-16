rule TTP_XOR_MULT_DOSStub_aed3 {
  strings:
    $key_aed3 = { fa bb [2] 8e a3 [2] c9 a1 [2] 8e b0 [2] c0 bc [2] cc b6 [2] db bd [2] c0 f3 [2] fd }

  condition:
    any of them
}