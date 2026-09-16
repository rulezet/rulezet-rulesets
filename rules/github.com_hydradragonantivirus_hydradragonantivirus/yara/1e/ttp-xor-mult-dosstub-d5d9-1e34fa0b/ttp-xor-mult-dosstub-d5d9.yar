rule TTP_XOR_MULT_DOSStub_d5d9 {
  strings:
    $key_d5d9 = { 81 b1 [2] f5 a9 [2] b2 ab [2] f5 ba [2] bb b6 [2] b7 bc [2] a0 b7 [2] bb f9 [2] 86 }

  condition:
    any of them
}