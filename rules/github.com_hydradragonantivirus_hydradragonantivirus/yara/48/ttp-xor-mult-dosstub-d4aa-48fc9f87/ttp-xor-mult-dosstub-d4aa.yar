rule TTP_XOR_MULT_DOSStub_d4aa {
  strings:
    $key_d4aa = { 80 c2 [2] f4 da [2] b3 d8 [2] f4 c9 [2] ba c5 [2] b6 cf [2] a1 c4 [2] ba 8a [2] 87 }

  condition:
    any of them
}