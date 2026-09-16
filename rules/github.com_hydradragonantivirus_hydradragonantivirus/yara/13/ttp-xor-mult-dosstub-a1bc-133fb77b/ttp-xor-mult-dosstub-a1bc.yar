rule TTP_XOR_MULT_DOSStub_a1bc {
  strings:
    $key_a1bc = { f5 d4 [2] 81 cc [2] c6 ce [2] 81 df [2] cf d3 [2] c3 d9 [2] d4 d2 [2] cf 9c [2] f2 }

  condition:
    any of them
}