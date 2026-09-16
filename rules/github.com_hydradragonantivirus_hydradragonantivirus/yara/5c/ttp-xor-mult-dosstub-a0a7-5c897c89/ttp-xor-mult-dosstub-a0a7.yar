rule TTP_XOR_MULT_DOSStub_a0a7 {
  strings:
    $key_a0a7 = { f4 cf [2] 80 d7 [2] c7 d5 [2] 80 c4 [2] ce c8 [2] c2 c2 [2] d5 c9 [2] ce 87 [2] f3 }

  condition:
    any of them
}