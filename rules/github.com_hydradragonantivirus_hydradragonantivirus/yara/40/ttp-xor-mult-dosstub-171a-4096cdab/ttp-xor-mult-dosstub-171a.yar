rule TTP_XOR_MULT_DOSStub_171a {
  strings:
    $key_171a = { 43 72 [2] 37 6a [2] 70 68 [2] 37 79 [2] 79 75 [2] 75 7f [2] 62 74 [2] 79 3a [2] 44 }

  condition:
    any of them
}