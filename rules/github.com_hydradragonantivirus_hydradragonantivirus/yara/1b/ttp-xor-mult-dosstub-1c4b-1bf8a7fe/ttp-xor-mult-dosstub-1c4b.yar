rule TTP_XOR_MULT_DOSStub_1c4b {
  strings:
    $key_1c4b = { 48 23 [2] 3c 3b [2] 7b 39 [2] 3c 28 [2] 72 24 [2] 7e 2e [2] 69 25 [2] 72 6b [2] 4f }

  condition:
    any of them
}