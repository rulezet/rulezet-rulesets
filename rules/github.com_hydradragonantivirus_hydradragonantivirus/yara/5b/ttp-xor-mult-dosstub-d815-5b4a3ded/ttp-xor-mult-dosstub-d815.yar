rule TTP_XOR_MULT_DOSStub_d815 {
  strings:
    $key_d815 = { 8c 7d [2] f8 65 [2] bf 67 [2] f8 76 [2] b6 7a [2] ba 70 [2] ad 7b [2] b6 35 [2] 8b }

  condition:
    any of them
}