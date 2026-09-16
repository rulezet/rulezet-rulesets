rule TTP_XOR_MULT_DOSStub_4204 {
  strings:
    $key_4204 = { 16 6c [2] 62 74 [2] 25 76 [2] 62 67 [2] 2c 6b [2] 20 61 [2] 37 6a [2] 2c 24 [2] 11 }

  condition:
    any of them
}