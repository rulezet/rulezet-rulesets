rule TTP_XOR_MULT_DOSStub_d846 {
  strings:
    $key_d846 = { 8c 2e [2] f8 36 [2] bf 34 [2] f8 25 [2] b6 29 [2] ba 23 [2] ad 28 [2] b6 66 [2] 8b }

  condition:
    any of them
}