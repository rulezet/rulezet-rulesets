rule TTP_XOR_MULT_DOSStub_d822 {
  strings:
    $key_d822 = { 8c 4a [2] f8 52 [2] bf 50 [2] f8 41 [2] b6 4d [2] ba 47 [2] ad 4c [2] b6 02 [2] 8b }

  condition:
    any of them
}