rule TTP_XOR_MULT_DOSStub_794a {
  strings:
    $key_794a = { 2d 22 [2] 59 3a [2] 1e 38 [2] 59 29 [2] 17 25 [2] 1b 2f [2] 0c 24 [2] 17 6a [2] 2a }

  condition:
    any of them
}