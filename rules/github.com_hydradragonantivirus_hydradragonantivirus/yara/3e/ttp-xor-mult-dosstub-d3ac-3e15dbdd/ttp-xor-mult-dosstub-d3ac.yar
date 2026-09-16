rule TTP_XOR_MULT_DOSStub_d3ac {
  strings:
    $key_d3ac = { 87 c4 [2] f3 dc [2] b4 de [2] f3 cf [2] bd c3 [2] b1 c9 [2] a6 c2 [2] bd 8c [2] 80 }

  condition:
    any of them
}