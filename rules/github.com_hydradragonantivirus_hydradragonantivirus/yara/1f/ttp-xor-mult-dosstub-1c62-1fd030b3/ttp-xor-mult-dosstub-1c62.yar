rule TTP_XOR_MULT_DOSStub_1c62 {
  strings:
    $key_1c62 = { 48 0a [2] 3c 12 [2] 7b 10 [2] 3c 01 [2] 72 0d [2] 7e 07 [2] 69 0c [2] 72 42 [2] 4f }

  condition:
    any of them
}