rule TTP_XOR_MULT_DOSStub_d5e0 {
  strings:
    $key_d5e0 = { 81 88 [2] f5 90 [2] b2 92 [2] f5 83 [2] bb 8f [2] b7 85 [2] a0 8e [2] bb c0 [2] 86 }

  condition:
    any of them
}