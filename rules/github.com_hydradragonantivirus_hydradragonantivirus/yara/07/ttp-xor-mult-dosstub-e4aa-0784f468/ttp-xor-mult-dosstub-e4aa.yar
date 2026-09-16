rule TTP_XOR_MULT_DOSStub_e4aa {
  strings:
    $key_e4aa = { b0 c2 [2] c4 da [2] 83 d8 [2] c4 c9 [2] 8a c5 [2] 86 cf [2] 91 c4 [2] 8a 8a [2] b7 }

  condition:
    any of them
}