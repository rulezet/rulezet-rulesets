rule TTP_XOR_MULT_DOSStub_1c04 {
  strings:
    $key_1c04 = { 48 6c [2] 3c 74 [2] 7b 76 [2] 3c 67 [2] 72 6b [2] 7e 61 [2] 69 6a [2] 72 24 [2] 4f }

  condition:
    any of them
}