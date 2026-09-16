rule TTP_XOR_MULT_DOSStub_d997 {
  strings:
    $key_d997 = { 8d ff [2] f9 e7 [2] be e5 [2] f9 f4 [2] b7 f8 [2] bb f2 [2] ac f9 [2] b7 b7 [2] 8a }

  condition:
    any of them
}