rule TTP_XOR_MULT_DOSStub_e6aa {
  strings:
    $key_e6aa = { b2 c2 [2] c6 da [2] 81 d8 [2] c6 c9 [2] 88 c5 [2] 84 cf [2] 93 c4 [2] 88 8a [2] b5 }

  condition:
    any of them
}