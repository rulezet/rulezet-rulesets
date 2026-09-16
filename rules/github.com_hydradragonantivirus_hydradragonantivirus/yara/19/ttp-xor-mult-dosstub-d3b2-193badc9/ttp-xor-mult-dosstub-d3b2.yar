rule TTP_XOR_MULT_DOSStub_d3b2 {
  strings:
    $key_d3b2 = { 87 da [2] f3 c2 [2] b4 c0 [2] f3 d1 [2] bd dd [2] b1 d7 [2] a6 dc [2] bd 92 [2] 80 }

  condition:
    any of them
}