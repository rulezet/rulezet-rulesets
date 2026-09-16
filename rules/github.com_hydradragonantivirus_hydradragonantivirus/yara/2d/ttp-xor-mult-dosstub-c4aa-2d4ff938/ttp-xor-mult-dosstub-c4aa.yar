rule TTP_XOR_MULT_DOSStub_c4aa {
  strings:
    $key_c4aa = { 90 c2 [2] e4 da [2] a3 d8 [2] e4 c9 [2] aa c5 [2] a6 cf [2] b1 c4 [2] aa 8a [2] 97 }

  condition:
    any of them
}