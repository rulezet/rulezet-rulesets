rule TTP_XOR_MULT_DOSStub_1c54 {
  strings:
    $key_1c54 = { 48 3c [2] 3c 24 [2] 7b 26 [2] 3c 37 [2] 72 3b [2] 7e 31 [2] 69 3a [2] 72 74 [2] 4f }

  condition:
    any of them
}