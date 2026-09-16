rule TTP_XOR_MULT_DOSStub_1c5a {
  strings:
    $key_1c5a = { 48 32 [2] 3c 2a [2] 7b 28 [2] 3c 39 [2] 72 35 [2] 7e 3f [2] 69 34 [2] 72 7a [2] 4f }

  condition:
    any of them
}