rule TTP_XOR_MULT_DOSStub_d337 {
  strings:
    $key_d337 = { 87 5f [2] f3 47 [2] b4 45 [2] f3 54 [2] bd 58 [2] b1 52 [2] a6 59 [2] bd 17 [2] 80 }

  condition:
    any of them
}