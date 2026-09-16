rule TTP_XOR_MULT_DOSStub_d596 {
  strings:
    $key_d596 = { 81 fe [2] f5 e6 [2] b2 e4 [2] f5 f5 [2] bb f9 [2] b7 f3 [2] a0 f8 [2] bb b6 [2] 86 }

  condition:
    any of them
}