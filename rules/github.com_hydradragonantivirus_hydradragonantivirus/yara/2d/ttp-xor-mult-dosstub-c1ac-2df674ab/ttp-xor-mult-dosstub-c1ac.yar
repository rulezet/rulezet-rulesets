rule TTP_XOR_MULT_DOSStub_c1ac {
  strings:
    $key_c1ac = { 95 c4 [2] e1 dc [2] a6 de [2] e1 cf [2] af c3 [2] a3 c9 [2] b4 c2 [2] af 8c [2] 92 }

  condition:
    any of them
}