rule TTP_XOR_MULT_DOSStub_d318 {
  strings:
    $key_d318 = { 87 70 [2] f3 68 [2] b4 6a [2] f3 7b [2] bd 77 [2] b1 7d [2] a6 76 [2] bd 38 [2] 80 }

  condition:
    any of them
}