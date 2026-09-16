rule TTP_XOR_MULT_DOSStub_2c0a {
  strings:
    $key_2c0a = { 78 62 [2] 0c 7a [2] 4b 78 [2] 0c 69 [2] 42 65 [2] 4e 6f [2] 59 64 [2] 42 2a [2] 7f }

  condition:
    any of them
}