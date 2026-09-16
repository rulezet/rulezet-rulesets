rule TTP_XOR_MULT_DOSStub_644a {
  strings:
    $key_644a = { 30 22 [2] 44 3a [2] 03 38 [2] 44 29 [2] 0a 25 [2] 06 2f [2] 11 24 [2] 0a 6a [2] 37 }

  condition:
    any of them
}