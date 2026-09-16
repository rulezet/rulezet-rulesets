rule TTP_XOR_MULT_DOSStub_d809 {
  strings:
    $key_d809 = { 8c 61 [2] f8 79 [2] bf 7b [2] f8 6a [2] b6 66 [2] ba 6c [2] ad 67 [2] b6 29 [2] 8b }

  condition:
    any of them
}