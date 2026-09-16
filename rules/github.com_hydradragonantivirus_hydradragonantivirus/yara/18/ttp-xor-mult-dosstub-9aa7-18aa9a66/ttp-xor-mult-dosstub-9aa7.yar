rule TTP_XOR_MULT_DOSStub_9aa7 {
  strings:
    $key_9aa7 = { ce cf [2] ba d7 [2] fd d5 [2] ba c4 [2] f4 c8 [2] f8 c2 [2] ef c9 [2] f4 87 [2] c9 }

  condition:
    any of them
}