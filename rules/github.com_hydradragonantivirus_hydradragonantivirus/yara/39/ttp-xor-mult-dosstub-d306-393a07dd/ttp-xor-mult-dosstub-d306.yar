rule TTP_XOR_MULT_DOSStub_d306 {
  strings:
    $key_d306 = { 87 6e [2] f3 76 [2] b4 74 [2] f3 65 [2] bd 69 [2] b1 63 [2] a6 68 [2] bd 26 [2] 80 }

  condition:
    any of them
}