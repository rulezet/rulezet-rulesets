rule TTP_XOR_MULT_DOSStub_d506 {
  strings:
    $key_d506 = { 81 6e [2] f5 76 [2] b2 74 [2] f5 65 [2] bb 69 [2] b7 63 [2] a0 68 [2] bb 26 [2] 86 }

  condition:
    any of them
}