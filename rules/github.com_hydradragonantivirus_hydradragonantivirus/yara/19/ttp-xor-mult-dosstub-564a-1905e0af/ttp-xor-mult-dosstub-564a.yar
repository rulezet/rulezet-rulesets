rule TTP_XOR_MULT_DOSStub_564a {
  strings:
    $key_564a = { 02 22 [2] 76 3a [2] 31 38 [2] 76 29 [2] 38 25 [2] 34 2f [2] 23 24 [2] 38 6a [2] 05 }

  condition:
    any of them
}