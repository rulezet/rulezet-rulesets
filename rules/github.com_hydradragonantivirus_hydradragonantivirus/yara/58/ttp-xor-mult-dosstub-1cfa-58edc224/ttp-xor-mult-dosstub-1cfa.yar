rule TTP_XOR_MULT_DOSStub_1cfa {
  strings:
    $key_1cfa = { 48 92 [2] 3c 8a [2] 7b 88 [2] 3c 99 [2] 72 95 [2] 7e 9f [2] 69 94 [2] 72 da [2] 4f }

  condition:
    any of them
}