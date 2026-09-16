rule TTP_XOR_MULT_DOSStub_d343 {
  strings:
    $key_d343 = { 87 2b [2] f3 33 [2] b4 31 [2] f3 20 [2] bd 2c [2] b1 26 [2] a6 2d [2] bd 63 [2] 80 }

  condition:
    any of them
}