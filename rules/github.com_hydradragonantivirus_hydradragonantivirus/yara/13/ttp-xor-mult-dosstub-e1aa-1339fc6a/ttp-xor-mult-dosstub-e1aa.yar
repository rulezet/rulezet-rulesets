rule TTP_XOR_MULT_DOSStub_e1aa {
  strings:
    $key_e1aa = { b5 c2 [2] c1 da [2] 86 d8 [2] c1 c9 [2] 8f c5 [2] 83 cf [2] 94 c4 [2] 8f 8a [2] b2 }

  condition:
    any of them
}