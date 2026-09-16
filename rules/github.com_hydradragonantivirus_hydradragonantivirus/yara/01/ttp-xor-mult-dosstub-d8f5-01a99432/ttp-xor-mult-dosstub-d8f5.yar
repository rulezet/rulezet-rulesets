rule TTP_XOR_MULT_DOSStub_d8f5 {
  strings:
    $key_d8f5 = { 8c 9d [2] f8 85 [2] bf 87 [2] f8 96 [2] b6 9a [2] ba 90 [2] ad 9b [2] b6 d5 [2] 8b }

  condition:
    any of them
}