rule TTP_XOR_MULT_DOSStub_d500 {
  strings:
    $key_d500 = { 81 68 [2] f5 70 [2] b2 72 [2] f5 63 [2] bb 6f [2] b7 65 [2] a0 6e [2] bb 20 [2] 86 }

  condition:
    any of them
}