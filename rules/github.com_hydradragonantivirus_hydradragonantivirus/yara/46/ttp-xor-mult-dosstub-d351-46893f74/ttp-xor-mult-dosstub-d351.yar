rule TTP_XOR_MULT_DOSStub_d351 {
  strings:
    $key_d351 = { 87 39 [2] f3 21 [2] b4 23 [2] f3 32 [2] bd 3e [2] b1 34 [2] a6 3f [2] bd 71 [2] 80 }

  condition:
    any of them
}