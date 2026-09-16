rule TTP_XOR_MULT_DOSStub_d3a8 {
  strings:
    $key_d3a8 = { 87 c0 [2] f3 d8 [2] b4 da [2] f3 cb [2] bd c7 [2] b1 cd [2] a6 c6 [2] bd 88 [2] 80 }

  condition:
    any of them
}