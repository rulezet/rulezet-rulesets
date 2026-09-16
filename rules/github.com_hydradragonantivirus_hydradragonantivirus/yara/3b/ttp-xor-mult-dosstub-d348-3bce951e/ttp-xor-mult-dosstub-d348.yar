rule TTP_XOR_MULT_DOSStub_d348 {
  strings:
    $key_d348 = { 87 20 [2] f3 38 [2] b4 3a [2] f3 2b [2] bd 27 [2] b1 2d [2] a6 26 [2] bd 68 [2] 80 }

  condition:
    any of them
}