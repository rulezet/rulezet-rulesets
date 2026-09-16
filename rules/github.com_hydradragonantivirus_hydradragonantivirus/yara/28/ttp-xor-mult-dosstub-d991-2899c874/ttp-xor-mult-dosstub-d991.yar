rule TTP_XOR_MULT_DOSStub_d991 {
  strings:
    $key_d991 = { 8d f9 [2] f9 e1 [2] be e3 [2] f9 f2 [2] b7 fe [2] bb f4 [2] ac ff [2] b7 b1 [2] 8a }

  condition:
    any of them
}