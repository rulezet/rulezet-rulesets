rule TTP_XOR_MULT_DOSStub_d5e7 {
  strings:
    $key_d5e7 = { 81 8f [2] f5 97 [2] b2 95 [2] f5 84 [2] bb 88 [2] b7 82 [2] a0 89 [2] bb c7 [2] 86 }

  condition:
    any of them
}