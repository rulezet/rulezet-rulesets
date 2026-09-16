rule TTP_XOR_MULT_DOSStub_d0c0 {
  strings:
    $key_d0c0 = { 84 a8 [2] f0 b0 [2] b7 b2 [2] f0 a3 [2] be af [2] b2 a5 [2] a5 ae [2] be e0 [2] 83 }

  condition:
    any of them
}