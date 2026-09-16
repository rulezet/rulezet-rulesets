rule TTP_XOR_MULT_DOSStub_201a {
  strings:
    $key_201a = { 74 72 [2] 00 6a [2] 47 68 [2] 00 79 [2] 4e 75 [2] 42 7f [2] 55 74 [2] 4e 3a [2] 73 }

  condition:
    any of them
}