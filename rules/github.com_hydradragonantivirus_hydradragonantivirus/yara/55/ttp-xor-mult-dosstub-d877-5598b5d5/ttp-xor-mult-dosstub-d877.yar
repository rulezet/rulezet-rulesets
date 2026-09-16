rule TTP_XOR_MULT_DOSStub_d877 {
  strings:
    $key_d877 = { 8c 1f [2] f8 07 [2] bf 05 [2] f8 14 [2] b6 18 [2] ba 12 [2] ad 19 [2] b6 57 [2] 8b }

  condition:
    any of them
}