rule TTP_XOR_MULT_DOSStub_d8f8 {
  strings:
    $key_d8f8 = { 8c 90 [2] f8 88 [2] bf 8a [2] f8 9b [2] b6 97 [2] ba 9d [2] ad 96 [2] b6 d8 [2] 8b }

  condition:
    any of them
}