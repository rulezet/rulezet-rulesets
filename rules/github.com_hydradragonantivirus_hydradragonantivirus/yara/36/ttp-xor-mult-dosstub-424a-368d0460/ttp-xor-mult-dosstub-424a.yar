rule TTP_XOR_MULT_DOSStub_424a {
  strings:
    $key_424a = { 16 22 [2] 62 3a [2] 25 38 [2] 62 29 [2] 2c 25 [2] 20 2f [2] 37 24 [2] 2c 6a [2] 11 }

  condition:
    any of them
}