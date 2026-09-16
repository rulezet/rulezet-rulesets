rule TTP_XOR_MULT_DOSStub_1c32 {
  strings:
    $key_1c32 = { 48 5a [2] 3c 42 [2] 7b 40 [2] 3c 51 [2] 72 5d [2] 7e 57 [2] 69 5c [2] 72 12 [2] 4f }

  condition:
    any of them
}