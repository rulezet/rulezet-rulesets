rule TTP_XOR_MULT_DOSStub_c2ac {
  strings:
    $key_c2ac = { 96 c4 [2] e2 dc [2] a5 de [2] e2 cf [2] ac c3 [2] a0 c9 [2] b7 c2 [2] ac 8c [2] 91 }

  condition:
    any of them
}