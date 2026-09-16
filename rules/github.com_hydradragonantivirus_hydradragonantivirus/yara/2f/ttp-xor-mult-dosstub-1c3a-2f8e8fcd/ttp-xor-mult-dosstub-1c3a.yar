rule TTP_XOR_MULT_DOSStub_1c3a {
  strings:
    $key_1c3a = { 48 52 [2] 3c 4a [2] 7b 48 [2] 3c 59 [2] 72 55 [2] 7e 5f [2] 69 54 [2] 72 1a [2] 4f }

  condition:
    any of them
}