rule TTP_XOR_MULT_DOSStub_1ce9 {
  strings:
    $key_1ce9 = { 48 81 [2] 3c 99 [2] 7b 9b [2] 3c 8a [2] 72 86 [2] 7e 8c [2] 69 87 [2] 72 c9 [2] 4f }

  condition:
    any of them
}