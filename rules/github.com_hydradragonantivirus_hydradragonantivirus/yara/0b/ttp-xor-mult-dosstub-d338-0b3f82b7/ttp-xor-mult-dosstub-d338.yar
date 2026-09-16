rule TTP_XOR_MULT_DOSStub_d338 {
  strings:
    $key_d338 = { 87 50 [2] f3 48 [2] b4 4a [2] f3 5b [2] bd 57 [2] b1 5d [2] a6 56 [2] bd 18 [2] 80 }

  condition:
    any of them
}