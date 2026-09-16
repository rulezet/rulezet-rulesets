rule TTP_XOR_MULT_DOSStub_d8f6 {
  strings:
    $key_d8f6 = { 8c 9e [2] f8 86 [2] bf 84 [2] f8 95 [2] b6 99 [2] ba 93 [2] ad 98 [2] b6 d6 [2] 8b }

  condition:
    any of them
}