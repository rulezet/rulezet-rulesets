rule TTP_XOR_MULT_DOSStub_d350 {
  strings:
    $key_d350 = { 87 38 [2] f3 20 [2] b4 22 [2] f3 33 [2] bd 3f [2] b1 35 [2] a6 3e [2] bd 70 [2] 80 }

  condition:
    any of them
}