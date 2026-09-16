rule TTP_XOR_MULT_DOSStub_1c0a {
  strings:
    $key_1c0a = { 48 62 [2] 3c 7a [2] 7b 78 [2] 3c 69 [2] 72 65 [2] 7e 6f [2] 69 64 [2] 72 2a [2] 4f }

  condition:
    any of them
}