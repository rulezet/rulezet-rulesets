rule TTP_XOR_MULT_DOSStub_a8b6 {
  strings:
    $key_a8b6 = { fc de [2] 88 c6 [2] cf c4 [2] 88 d5 [2] c6 d9 [2] ca d3 [2] dd d8 [2] c6 96 [2] fb }

  condition:
    any of them
}