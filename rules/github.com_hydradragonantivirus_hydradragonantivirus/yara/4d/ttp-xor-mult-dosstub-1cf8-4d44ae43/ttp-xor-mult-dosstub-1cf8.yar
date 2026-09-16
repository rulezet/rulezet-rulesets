rule TTP_XOR_MULT_DOSStub_1cf8 {
  strings:
    $key_1cf8 = { 48 90 [2] 3c 88 [2] 7b 8a [2] 3c 9b [2] 72 97 [2] 7e 9d [2] 69 96 [2] 72 d8 [2] 4f }

  condition:
    any of them
}