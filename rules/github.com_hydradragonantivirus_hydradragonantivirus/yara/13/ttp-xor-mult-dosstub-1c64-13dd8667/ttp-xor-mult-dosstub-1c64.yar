rule TTP_XOR_MULT_DOSStub_1c64 {
  strings:
    $key_1c64 = { 48 0c [2] 3c 14 [2] 7b 16 [2] 3c 07 [2] 72 0b [2] 7e 01 [2] 69 0a [2] 72 44 [2] 4f }

  condition:
    any of them
}