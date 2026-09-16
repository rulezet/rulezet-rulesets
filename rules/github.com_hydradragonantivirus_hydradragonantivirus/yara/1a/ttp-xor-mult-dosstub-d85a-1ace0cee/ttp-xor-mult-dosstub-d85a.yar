rule TTP_XOR_MULT_DOSStub_d85a {
  strings:
    $key_d85a = { 8c 32 [2] f8 2a [2] bf 28 [2] f8 39 [2] b6 35 [2] ba 3f [2] ad 34 [2] b6 7a [2] 8b }

  condition:
    any of them
}