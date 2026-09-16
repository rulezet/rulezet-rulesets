rule TTP_XOR_MULT_DOSStub_d354 {
  strings:
    $key_d354 = { 87 3c [2] f3 24 [2] b4 26 [2] f3 37 [2] bd 3b [2] b1 31 [2] a6 3a [2] bd 74 [2] 80 }

  condition:
    any of them
}