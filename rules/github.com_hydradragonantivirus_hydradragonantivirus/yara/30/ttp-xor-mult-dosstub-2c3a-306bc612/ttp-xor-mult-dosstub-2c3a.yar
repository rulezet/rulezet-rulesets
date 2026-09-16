rule TTP_XOR_MULT_DOSStub_2c3a {
  strings:
    $key_2c3a = { 78 52 [2] 0c 4a [2] 4b 48 [2] 0c 59 [2] 42 55 [2] 4e 5f [2] 59 54 [2] 42 1a [2] 7f }

  condition:
    any of them
}