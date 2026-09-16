rule TTP_XOR_MULT_DOSStub_a8a4 {
  strings:
    $key_a8a4 = { fc cc [2] 88 d4 [2] cf d6 [2] 88 c7 [2] c6 cb [2] ca c1 [2] dd ca [2] c6 84 [2] fb }

  condition:
    any of them
}