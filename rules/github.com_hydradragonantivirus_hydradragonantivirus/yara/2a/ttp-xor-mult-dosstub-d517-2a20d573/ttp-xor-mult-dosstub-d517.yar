rule TTP_XOR_MULT_DOSStub_d517 {
  strings:
    $key_d517 = { 81 7f [2] f5 67 [2] b2 65 [2] f5 74 [2] bb 78 [2] b7 72 [2] a0 79 [2] bb 37 [2] 86 }

  condition:
    any of them
}