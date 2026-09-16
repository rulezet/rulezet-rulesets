rule TTP_XOR_MULT_DOSStub_90aa {
  strings:
    $key_90aa = { c4 c2 [2] b0 da [2] f7 d8 [2] b0 c9 [2] fe c5 [2] f2 cf [2] e5 c4 [2] fe 8a [2] c3 }

  condition:
    any of them
}