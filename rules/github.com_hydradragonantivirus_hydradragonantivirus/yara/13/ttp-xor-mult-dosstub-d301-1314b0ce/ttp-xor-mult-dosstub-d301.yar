rule TTP_XOR_MULT_DOSStub_d301 {
  strings:
    $key_d301 = { 87 69 [2] f3 71 [2] b4 73 [2] f3 62 [2] bd 6e [2] b1 64 [2] a6 6f [2] bd 21 [2] 80 }

  condition:
    any of them
}