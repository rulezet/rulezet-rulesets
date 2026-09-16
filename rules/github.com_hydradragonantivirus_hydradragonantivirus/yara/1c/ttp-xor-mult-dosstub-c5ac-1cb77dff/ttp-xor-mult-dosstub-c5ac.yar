rule TTP_XOR_MULT_DOSStub_c5ac {
  strings:
    $key_c5ac = { 91 c4 [2] e5 dc [2] a2 de [2] e5 cf [2] ab c3 [2] a7 c9 [2] b0 c2 [2] ab 8c [2] 96 }

  condition:
    any of them
}