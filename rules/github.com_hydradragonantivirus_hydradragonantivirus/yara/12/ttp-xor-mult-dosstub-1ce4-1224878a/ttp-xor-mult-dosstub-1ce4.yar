rule TTP_XOR_MULT_DOSStub_1ce4 {
  strings:
    $key_1ce4 = { 48 8c [2] 3c 94 [2] 7b 96 [2] 3c 87 [2] 72 8b [2] 7e 81 [2] 69 8a [2] 72 c4 [2] 4f }

  condition:
    any of them
}