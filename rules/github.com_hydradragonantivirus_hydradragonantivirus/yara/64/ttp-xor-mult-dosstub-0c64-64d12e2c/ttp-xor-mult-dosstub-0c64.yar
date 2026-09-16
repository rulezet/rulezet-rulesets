rule TTP_XOR_MULT_DOSStub_0c64 {
  strings:
    $key_0c64 = { 58 0c [2] 2c 14 [2] 6b 16 [2] 2c 07 [2] 62 0b [2] 6e 01 [2] 79 0a [2] 62 44 [2] 5f }

  condition:
    any of them
}