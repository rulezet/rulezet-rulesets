rule TTP_XOR_MULT_DOSStub_d7aa {
  strings:
    $key_d7aa = { 83 c2 [2] f7 da [2] b0 d8 [2] f7 c9 [2] b9 c5 [2] b5 cf [2] a2 c4 [2] b9 8a [2] 84 }

  condition:
    any of them
}