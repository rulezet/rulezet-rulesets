rule TTP_XOR_MULT_DOSStub_42f5 {
  strings:
    $key_42f5 = { 16 9d [2] 62 85 [2] 25 87 [2] 62 96 [2] 2c 9a [2] 20 90 [2] 37 9b [2] 2c d5 [2] 11 }

  condition:
    any of them
}