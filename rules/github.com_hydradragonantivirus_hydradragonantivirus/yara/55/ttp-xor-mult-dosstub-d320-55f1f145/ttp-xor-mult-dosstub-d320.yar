rule TTP_XOR_MULT_DOSStub_d320 {
  strings:
    $key_d320 = { 87 48 [2] f3 50 [2] b4 52 [2] f3 43 [2] bd 4f [2] b1 45 [2] a6 4e [2] bd 00 [2] 80 }

  condition:
    any of them
}