rule TTP_XOR_MULT_DOSStub_95aa {
  strings:
    $key_95aa = { c1 c2 [2] b5 da [2] f2 d8 [2] b5 c9 [2] fb c5 [2] f7 cf [2] e0 c4 [2] fb 8a [2] c6 }

  condition:
    any of them
}