rule TTP_XOR_MULT_DOSStub_d3f1 {
  strings:
    $key_d3f1 = { 87 99 [2] f3 81 [2] b4 83 [2] f3 92 [2] bd 9e [2] b1 94 [2] a6 9f [2] bd d1 [2] 80 }

  condition:
    any of them
}