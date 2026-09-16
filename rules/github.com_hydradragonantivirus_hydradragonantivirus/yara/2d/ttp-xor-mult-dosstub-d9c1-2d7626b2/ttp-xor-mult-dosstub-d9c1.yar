rule TTP_XOR_MULT_DOSStub_d9c1 {
  strings:
    $key_d9c1 = { 8d a9 [2] f9 b1 [2] be b3 [2] f9 a2 [2] b7 ae [2] bb a4 [2] ac af [2] b7 e1 [2] 8a }

  condition:
    any of them
}