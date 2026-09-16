rule TTP_XOR_MULT_DOSStub_c1aa {
  strings:
    $key_c1aa = { 95 c2 [2] e1 da [2] a6 d8 [2] e1 c9 [2] af c5 [2] a3 cf [2] b4 c4 [2] af 8a [2] 92 }

  condition:
    any of them
}