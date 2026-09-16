rule TTP_XOR_MULT_DOSStub_d331 {
  strings:
    $key_d331 = { 87 59 [2] f3 41 [2] b4 43 [2] f3 52 [2] bd 5e [2] b1 54 [2] a6 5f [2] bd 11 [2] 80 }

  condition:
    any of them
}