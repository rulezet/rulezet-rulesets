rule TTP_XOR_MULT_DOSStub_1c65 {
  strings:
    $key_1c65 = { 48 0d [2] 3c 15 [2] 7b 17 [2] 3c 06 [2] 72 0a [2] 7e 00 [2] 69 0b [2] 72 45 [2] 4f }

  condition:
    any of them
}