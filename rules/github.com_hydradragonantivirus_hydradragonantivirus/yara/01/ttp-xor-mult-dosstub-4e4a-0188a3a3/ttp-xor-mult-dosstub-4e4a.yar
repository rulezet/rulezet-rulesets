rule TTP_XOR_MULT_DOSStub_4e4a {
  strings:
    $key_4e4a = { 1a 22 [2] 6e 3a [2] 29 38 [2] 6e 29 [2] 20 25 [2] 2c 2f [2] 3b 24 [2] 20 6a [2] 1d }

  condition:
    any of them
}