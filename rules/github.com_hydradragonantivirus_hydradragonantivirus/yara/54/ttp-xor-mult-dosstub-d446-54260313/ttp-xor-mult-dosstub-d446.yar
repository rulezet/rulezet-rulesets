rule TTP_XOR_MULT_DOSStub_d446 {
  strings:
    $key_d446 = { 80 2e [2] f4 36 [2] b3 34 [2] f4 25 [2] ba 29 [2] b6 23 [2] a1 28 [2] ba 66 [2] 87 }

  condition:
    any of them
}