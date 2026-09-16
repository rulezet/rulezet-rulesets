rule TTP_XOR_MULT_DOSStub_a4bc {
  strings:
    $key_a4bc = { f0 d4 [2] 84 cc [2] c3 ce [2] 84 df [2] ca d3 [2] c6 d9 [2] d1 d2 [2] ca 9c [2] f7 }

  condition:
    any of them
}