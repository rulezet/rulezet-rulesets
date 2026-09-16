rule TTP_XOR_MULT_DOSStub_aeb6 {
  strings:
    $key_aeb6 = { fa de [2] 8e c6 [2] c9 c4 [2] 8e d5 [2] c0 d9 [2] cc d3 [2] db d8 [2] c0 96 [2] fd }

  condition:
    any of them
}