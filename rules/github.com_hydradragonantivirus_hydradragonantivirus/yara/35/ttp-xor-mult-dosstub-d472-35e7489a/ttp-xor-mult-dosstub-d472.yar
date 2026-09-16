rule TTP_XOR_MULT_DOSStub_d472 {
  strings:
    $key_d472 = { 80 1a [2] f4 02 [2] b3 00 [2] f4 11 [2] ba 1d [2] b6 17 [2] a1 1c [2] ba 52 [2] 87 }

  condition:
    any of them
}