rule TTP_XOR_MULT_DOSStub_d349 {
  strings:
    $key_d349 = { 87 21 [2] f3 39 [2] b4 3b [2] f3 2a [2] bd 26 [2] b1 2c [2] a6 27 [2] bd 69 [2] 80 }

  condition:
    any of them
}