rule TTP_XOR_MULT_DOSStub_1c34 {
  strings:
    $key_1c34 = { 48 5c [2] 3c 44 [2] 7b 46 [2] 3c 57 [2] 72 5b [2] 7e 51 [2] 69 5a [2] 72 14 [2] 4f }

  condition:
    any of them
}