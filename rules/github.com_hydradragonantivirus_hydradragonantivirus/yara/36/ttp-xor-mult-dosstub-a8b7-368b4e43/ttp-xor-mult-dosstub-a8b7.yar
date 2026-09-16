rule TTP_XOR_MULT_DOSStub_a8b7 {
  strings:
    $key_a8b7 = { fc df [2] 88 c7 [2] cf c5 [2] 88 d4 [2] c6 d8 [2] ca d2 [2] dd d9 [2] c6 97 [2] fb }

  condition:
    any of them
}