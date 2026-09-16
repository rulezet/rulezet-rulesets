rule TTP_XOR_MULT_DOSStub_d8f7 {
  strings:
    $key_d8f7 = { 8c 9f [2] f8 87 [2] bf 85 [2] f8 94 [2] b6 98 [2] ba 92 [2] ad 99 [2] b6 d7 [2] 8b }

  condition:
    any of them
}