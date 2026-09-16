rule TTP_XOR_MULT_DOSStub_9aa1 {
  strings:
    $key_9aa1 = { ce c9 [2] ba d1 [2] fd d3 [2] ba c2 [2] f4 ce [2] f8 c4 [2] ef cf [2] f4 81 [2] c9 }

  condition:
    any of them
}