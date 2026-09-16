rule TTP_XOR_MULT_DOSStub_457a {
  strings:
    $key_457a = { 11 12 [2] 65 0a [2] 22 08 [2] 65 19 [2] 2b 15 [2] 27 1f [2] 30 14 [2] 2b 5a [2] 16 }

  condition:
    any of them
}