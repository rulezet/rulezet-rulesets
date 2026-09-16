rule TTP_XOR_MULT_DOSStub_d8e8 {
  strings:
    $key_d8e8 = { 8c 80 [2] f8 98 [2] bf 9a [2] f8 8b [2] b6 87 [2] ba 8d [2] ad 86 [2] b6 c8 [2] 8b }

  condition:
    any of them
}