rule TTP_XOR_MULT_DOSStub_d8f0 {
  strings:
    $key_d8f0 = { 8c 98 [2] f8 80 [2] bf 82 [2] f8 93 [2] b6 9f [2] ba 95 [2] ad 9e [2] b6 d0 [2] 8b }

  condition:
    any of them
}