rule TTP_XOR_MULT_DOSStub_d864 {
  strings:
    $key_d864 = { 8c 0c [2] f8 14 [2] bf 16 [2] f8 07 [2] b6 0b [2] ba 01 [2] ad 0a [2] b6 44 [2] 8b }

  condition:
    any of them
}