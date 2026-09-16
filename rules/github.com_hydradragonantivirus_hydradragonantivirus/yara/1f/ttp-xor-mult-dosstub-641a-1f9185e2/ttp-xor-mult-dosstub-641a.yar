rule TTP_XOR_MULT_DOSStub_641a {
  strings:
    $key_641a = { 30 72 [2] 44 6a [2] 03 68 [2] 44 79 [2] 0a 75 [2] 06 7f [2] 11 74 [2] 0a 3a [2] 37 }

  condition:
    any of them
}