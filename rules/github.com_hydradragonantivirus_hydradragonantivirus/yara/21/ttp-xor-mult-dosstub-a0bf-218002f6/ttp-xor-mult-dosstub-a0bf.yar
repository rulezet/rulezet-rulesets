rule TTP_XOR_MULT_DOSStub_a0bf {
  strings:
    $key_a0bf = { f4 d7 [2] 80 cf [2] c7 cd [2] 80 dc [2] ce d0 [2] c2 da [2] d5 d1 [2] ce 9f [2] f3 }

  condition:
    any of them
}