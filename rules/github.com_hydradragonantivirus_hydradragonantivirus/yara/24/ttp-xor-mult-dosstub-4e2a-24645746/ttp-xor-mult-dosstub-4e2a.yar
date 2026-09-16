rule TTP_XOR_MULT_DOSStub_4e2a {
  strings:
    $key_4e2a = { 1a 42 [2] 6e 5a [2] 29 58 [2] 6e 49 [2] 20 45 [2] 2c 4f [2] 3b 44 [2] 20 0a [2] 1d }

  condition:
    any of them
}