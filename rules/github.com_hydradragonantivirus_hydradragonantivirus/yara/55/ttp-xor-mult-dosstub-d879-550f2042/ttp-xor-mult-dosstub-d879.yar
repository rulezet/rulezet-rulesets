rule TTP_XOR_MULT_DOSStub_d879 {
  strings:
    $key_d879 = { 8c 11 [2] f8 09 [2] bf 0b [2] f8 1a [2] b6 16 [2] ba 1c [2] ad 17 [2] b6 59 [2] 8b }

  condition:
    any of them
}