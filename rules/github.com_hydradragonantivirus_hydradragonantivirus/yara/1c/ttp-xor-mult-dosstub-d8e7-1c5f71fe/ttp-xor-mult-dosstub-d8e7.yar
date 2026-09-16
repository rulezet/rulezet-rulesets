rule TTP_XOR_MULT_DOSStub_d8e7 {
  strings:
    $key_d8e7 = { 8c 8f [2] f8 97 [2] bf 95 [2] f8 84 [2] b6 88 [2] ba 82 [2] ad 89 [2] b6 c7 [2] 8b }

  condition:
    any of them
}