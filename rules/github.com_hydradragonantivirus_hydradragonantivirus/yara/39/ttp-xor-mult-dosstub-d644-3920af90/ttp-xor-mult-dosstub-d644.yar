rule TTP_XOR_MULT_DOSStub_d644 {
  strings:
    $key_d644 = { 82 2c [2] f6 34 [2] b1 36 [2] f6 27 [2] b8 2b [2] b4 21 [2] a3 2a [2] b8 64 [2] 85 }

  condition:
    any of them
}