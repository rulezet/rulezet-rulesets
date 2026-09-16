rule TTP_XOR_MULT_DOSStub_4264 {
  strings:
    $key_4264 = { 16 0c [2] 62 14 [2] 25 16 [2] 62 07 [2] 2c 0b [2] 20 01 [2] 37 0a [2] 2c 44 [2] 11 }

  condition:
    any of them
}