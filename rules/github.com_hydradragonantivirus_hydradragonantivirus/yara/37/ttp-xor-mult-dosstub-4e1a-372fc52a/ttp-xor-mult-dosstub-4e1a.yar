rule TTP_XOR_MULT_DOSStub_4e1a {
  strings:
    $key_4e1a = { 1a 72 [2] 6e 6a [2] 29 68 [2] 6e 79 [2] 20 75 [2] 2c 7f [2] 3b 74 [2] 20 3a [2] 1d }

  condition:
    any of them
}