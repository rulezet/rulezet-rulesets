rule TTP_XOR_MULT_DOSStub_324a {
  strings:
    $key_324a = { 66 22 [2] 12 3a [2] 55 38 [2] 12 29 [2] 5c 25 [2] 50 2f [2] 47 24 [2] 5c 6a [2] 61 }

  condition:
    any of them
}