rule TTP_XOR_MULT_DOSStub_d0c6 {
  strings:
    $key_d0c6 = { 84 ae [2] f0 b6 [2] b7 b4 [2] f0 a5 [2] be a9 [2] b2 a3 [2] a5 a8 [2] be e6 [2] 83 }

  condition:
    any of them
}