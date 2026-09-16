rule TTP_XOR_MULT_DOSStub_1cf9 {
  strings:
    $key_1cf9 = { 48 91 [2] 3c 89 [2] 7b 8b [2] 3c 9a [2] 72 96 [2] 7e 9c [2] 69 97 [2] 72 d9 [2] 4f }

  condition:
    any of them
}