rule TTP_XOR_MULT_DOSStub_d9c4 {
  strings:
    $key_d9c4 = { 8d ac [2] f9 b4 [2] be b6 [2] f9 a7 [2] b7 ab [2] bb a1 [2] ac aa [2] b7 e4 [2] 8a }

  condition:
    any of them
}