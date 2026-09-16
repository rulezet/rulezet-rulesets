rule TTP_XOR_MULT_DOSStub_d359 {
  strings:
    $key_d359 = { 87 31 [2] f3 29 [2] b4 2b [2] f3 3a [2] bd 36 [2] b1 3c [2] a6 37 [2] bd 79 [2] 80 }

  condition:
    any of them
}