rule TTP_XOR_MULT_DOSStub_d800 {
  strings:
    $key_d800 = { 8c 68 [2] f8 70 [2] bf 72 [2] f8 63 [2] b6 6f [2] ba 65 [2] ad 6e [2] b6 20 [2] 8b }

  condition:
    any of them
}