rule TTP_XOR_MULT_DOSStub_d3f7 {
  strings:
    $key_d3f7 = { 87 9f [2] f3 87 [2] b4 85 [2] f3 94 [2] bd 98 [2] b1 92 [2] a6 99 [2] bd d7 [2] 80 }

  condition:
    any of them
}