rule TTP_XOR_MULT_DOSStub_d8e6 {
  strings:
    $key_d8e6 = { 8c 8e [2] f8 96 [2] bf 94 [2] f8 85 [2] b6 89 [2] ba 83 [2] ad 88 [2] b6 c6 [2] 8b }

  condition:
    any of them
}