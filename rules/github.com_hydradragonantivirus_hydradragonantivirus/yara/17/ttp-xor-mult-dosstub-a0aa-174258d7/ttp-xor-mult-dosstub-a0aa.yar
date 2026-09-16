rule TTP_XOR_MULT_DOSStub_a0aa {
  strings:
    $key_a0aa = { f4 c2 [2] 80 da [2] c7 d8 [2] 80 c9 [2] ce c5 [2] c2 cf [2] d5 c4 [2] ce 8a [2] f3 }

  condition:
    any of them
}