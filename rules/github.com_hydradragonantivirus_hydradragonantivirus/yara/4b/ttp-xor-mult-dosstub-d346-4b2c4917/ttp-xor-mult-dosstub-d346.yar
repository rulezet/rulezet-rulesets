rule TTP_XOR_MULT_DOSStub_d346 {
  strings:
    $key_d346 = { 87 2e [2] f3 36 [2] b4 34 [2] f3 25 [2] bd 29 [2] b1 23 [2] a6 28 [2] bd 66 [2] 80 }

  condition:
    any of them
}