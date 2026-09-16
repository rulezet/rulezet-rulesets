rule TTP_XOR_MULT_DOSStub_14aa {
  strings:
    $key_14aa = { 40 c2 [2] 34 da [2] 73 d8 [2] 34 c9 [2] 7a c5 [2] 76 cf [2] 61 c4 [2] 7a 8a [2] 47 }

  condition:
    any of them
}