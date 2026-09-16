rule TTP_XOR_MULT_DOSStub_401a {
  strings:
    $key_401a = { 14 72 [2] 60 6a [2] 27 68 [2] 60 79 [2] 2e 75 [2] 22 7f [2] 35 74 [2] 2e 3a [2] 13 }

  condition:
    any of them
}