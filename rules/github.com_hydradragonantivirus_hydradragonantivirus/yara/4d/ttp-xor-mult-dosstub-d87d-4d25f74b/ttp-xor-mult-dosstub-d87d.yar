rule TTP_XOR_MULT_DOSStub_d87d {
  strings:
    $key_d87d = { 8c 15 [2] f8 0d [2] bf 0f [2] f8 1e [2] b6 12 [2] ba 18 [2] ad 13 [2] b6 5d [2] 8b }

  condition:
    any of them
}