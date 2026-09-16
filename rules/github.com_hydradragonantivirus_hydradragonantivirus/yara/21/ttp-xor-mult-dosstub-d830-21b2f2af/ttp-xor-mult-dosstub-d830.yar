rule TTP_XOR_MULT_DOSStub_d830 {
  strings:
    $key_d830 = { 8c 58 [2] f8 40 [2] bf 42 [2] f8 53 [2] b6 5f [2] ba 55 [2] ad 5e [2] b6 10 [2] 8b }

  condition:
    any of them
}