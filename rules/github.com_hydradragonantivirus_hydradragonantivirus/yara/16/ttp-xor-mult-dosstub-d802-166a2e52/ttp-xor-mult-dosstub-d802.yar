rule TTP_XOR_MULT_DOSStub_d802 {
  strings:
    $key_d802 = { 8c 6a [2] f8 72 [2] bf 70 [2] f8 61 [2] b6 6d [2] ba 67 [2] ad 6c [2] b6 22 [2] 8b }

  condition:
    any of them
}