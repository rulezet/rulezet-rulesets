rule TTP_XOR_MULT_DOSStub_d8ee {
  strings:
    $key_d8ee = { 8c 86 [2] f8 9e [2] bf 9c [2] f8 8d [2] b6 81 [2] ba 8b [2] ad 80 [2] b6 ce [2] 8b }

  condition:
    any of them
}