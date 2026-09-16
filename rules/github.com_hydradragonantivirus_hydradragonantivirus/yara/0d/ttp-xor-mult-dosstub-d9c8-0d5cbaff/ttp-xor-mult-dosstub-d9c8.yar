rule TTP_XOR_MULT_DOSStub_d9c8 {
  strings:
    $key_d9c8 = { 8d a0 [2] f9 b8 [2] be ba [2] f9 ab [2] b7 a7 [2] bb ad [2] ac a6 [2] b7 e8 [2] 8a }

  condition:
    any of them
}