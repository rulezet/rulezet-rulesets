rule TTP_XOR_MULT_DOSStub_d847 {
  strings:
    $key_d847 = { 8c 2f [2] f8 37 [2] bf 35 [2] f8 24 [2] b6 28 [2] ba 22 [2] ad 29 [2] b6 67 [2] 8b }

  condition:
    any of them
}