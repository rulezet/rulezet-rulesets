rule TTP_XOR_MULT_DOSStub_d83a {
  strings:
    $key_d83a = { 8c 52 [2] f8 4a [2] bf 48 [2] f8 59 [2] b6 55 [2] ba 5f [2] ad 54 [2] b6 1a [2] 8b }

  condition:
    any of them
}