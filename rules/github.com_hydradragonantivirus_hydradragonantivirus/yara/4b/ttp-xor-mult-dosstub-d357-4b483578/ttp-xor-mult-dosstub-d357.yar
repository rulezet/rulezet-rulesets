rule TTP_XOR_MULT_DOSStub_d357 {
  strings:
    $key_d357 = { 87 3f [2] f3 27 [2] b4 25 [2] f3 34 [2] bd 38 [2] b1 32 [2] a6 39 [2] bd 77 [2] 80 }

  condition:
    any of them
}