rule TTP_XOR_MULT_DOSStub_a2bc {
  strings:
    $key_a2bc = { f6 d4 [2] 82 cc [2] c5 ce [2] 82 df [2] cc d3 [2] c0 d9 [2] d7 d2 [2] cc 9c [2] f1 }

  condition:
    any of them
}