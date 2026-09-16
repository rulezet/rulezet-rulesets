rule TTP_XOR_MULT_DOSStub_d854 {
  strings:
    $key_d854 = { 8c 3c [2] f8 24 [2] bf 26 [2] f8 37 [2] b6 3b [2] ba 31 [2] ad 3a [2] b6 74 [2] 8b }

  condition:
    any of them
}