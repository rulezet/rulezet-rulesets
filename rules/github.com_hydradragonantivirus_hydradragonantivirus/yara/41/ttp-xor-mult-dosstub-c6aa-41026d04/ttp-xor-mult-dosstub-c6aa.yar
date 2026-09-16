rule TTP_XOR_MULT_DOSStub_c6aa {
  strings:
    $key_c6aa = { 92 c2 [2] e6 da [2] a1 d8 [2] e6 c9 [2] a8 c5 [2] a4 cf [2] b3 c4 [2] a8 8a [2] 95 }

  condition:
    any of them
}