rule TTP_XOR_MULT_DOSStub_d042 {
  strings:
    $key_d042 = { 84 2a [2] f0 32 [2] b7 30 [2] f0 21 [2] be 2d [2] b2 27 [2] a5 2c [2] be 62 [2] 83 }

  condition:
    any of them
}