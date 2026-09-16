rule TTP_XOR_MULT_DOSStub_d672 {
  strings:
    $key_d672 = { 82 1a [2] f6 02 [2] b1 00 [2] f6 11 [2] b8 1d [2] b4 17 [2] a3 1c [2] b8 52 [2] 85 }

  condition:
    any of them
}