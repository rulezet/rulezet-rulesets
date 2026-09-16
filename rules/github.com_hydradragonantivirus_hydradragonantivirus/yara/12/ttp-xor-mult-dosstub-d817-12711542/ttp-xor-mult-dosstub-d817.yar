rule TTP_XOR_MULT_DOSStub_d817 {
  strings:
    $key_d817 = { 8c 7f [2] f8 67 [2] bf 65 [2] f8 74 [2] b6 78 [2] ba 72 [2] ad 79 [2] b6 37 [2] 8b }

  condition:
    any of them
}