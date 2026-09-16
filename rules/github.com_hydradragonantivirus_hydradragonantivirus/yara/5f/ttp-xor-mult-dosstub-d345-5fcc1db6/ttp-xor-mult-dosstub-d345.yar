rule TTP_XOR_MULT_DOSStub_d345 {
  strings:
    $key_d345 = { 87 2d [2] f3 35 [2] b4 37 [2] f3 26 [2] bd 2a [2] b1 20 [2] a6 2b [2] bd 65 [2] 80 }

  condition:
    any of them
}