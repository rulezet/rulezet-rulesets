rule TTP_XOR_MULT_DOSStub_4e3a {
  strings:
    $key_4e3a = { 1a 52 [2] 6e 4a [2] 29 48 [2] 6e 59 [2] 20 55 [2] 2c 5f [2] 3b 54 [2] 20 1a [2] 1d }

  condition:
    any of them
}