rule TTP_XOR_MULT_DOSStub_d839 {
  strings:
    $key_d839 = { 8c 51 [2] f8 49 [2] bf 4b [2] f8 5a [2] b6 56 [2] ba 5c [2] ad 57 [2] b6 19 [2] 8b }

  condition:
    any of them
}