rule TTP_XOR_MULT_DOSStub_d87a {
  strings:
    $key_d87a = { 8c 12 [2] f8 0a [2] bf 08 [2] f8 19 [2] b6 15 [2] ba 1f [2] ad 14 [2] b6 5a [2] 8b }

  condition:
    any of them
}