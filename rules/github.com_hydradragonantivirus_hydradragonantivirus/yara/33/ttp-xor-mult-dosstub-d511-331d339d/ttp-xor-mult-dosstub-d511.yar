rule TTP_XOR_MULT_DOSStub_d511 {
  strings:
    $key_d511 = { 81 79 [2] f5 61 [2] b2 63 [2] f5 72 [2] bb 7e [2] b7 74 [2] a0 7f [2] bb 31 [2] 86 }

  condition:
    any of them
}