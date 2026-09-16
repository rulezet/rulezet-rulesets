rule TTP_XOR_MULT_DOSStub_a8b9 {
  strings:
    $key_a8b9 = { fc d1 [2] 88 c9 [2] cf cb [2] 88 da [2] c6 d6 [2] ca dc [2] dd d7 [2] c6 99 [2] fb }

  condition:
    any of them
}