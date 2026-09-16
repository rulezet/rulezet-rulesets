rule TTP_XOR_MULT_DOSStub_d3f5 {
  strings:
    $key_d3f5 = { 87 9d [2] f3 85 [2] b4 87 [2] f3 96 [2] bd 9a [2] b1 90 [2] a6 9b [2] bd d5 [2] 80 }

  condition:
    any of them
}