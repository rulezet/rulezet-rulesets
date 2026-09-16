rule TTP_XOR_MULT_DOSStub_d832 {
  strings:
    $key_d832 = { 8c 5a [2] f8 42 [2] bf 40 [2] f8 51 [2] b6 5d [2] ba 57 [2] ad 5c [2] b6 12 [2] 8b }

  condition:
    any of them
}