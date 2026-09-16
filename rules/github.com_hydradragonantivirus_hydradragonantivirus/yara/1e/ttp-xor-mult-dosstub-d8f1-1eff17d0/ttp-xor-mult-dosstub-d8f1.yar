rule TTP_XOR_MULT_DOSStub_d8f1 {
  strings:
    $key_d8f1 = { 8c 99 [2] f8 81 [2] bf 83 [2] f8 92 [2] b6 9e [2] ba 94 [2] ad 9f [2] b6 d1 [2] 8b }

  condition:
    any of them
}