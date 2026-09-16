rule TTP_XOR_MULT_DOSStub_d805 {
  strings:
    $key_d805 = { 8c 6d [2] f8 75 [2] bf 77 [2] f8 66 [2] b6 6a [2] ba 60 [2] ad 6b [2] b6 25 [2] 8b }

  condition:
    any of them
}