rule TTP_XOR_MULT_DOSStub_d8fa {
  strings:
    $key_d8fa = { 8c 92 [2] f8 8a [2] bf 88 [2] f8 99 [2] b6 95 [2] ba 9f [2] ad 94 [2] b6 da [2] 8b }

  condition:
    any of them
}