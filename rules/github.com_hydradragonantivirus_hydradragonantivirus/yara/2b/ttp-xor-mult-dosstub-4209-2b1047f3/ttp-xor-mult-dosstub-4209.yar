rule TTP_XOR_MULT_DOSStub_4209 {
  strings:
    $key_4209 = { 16 61 [2] 62 79 [2] 25 7b [2] 62 6a [2] 2c 66 [2] 20 6c [2] 37 67 [2] 2c 29 [2] 11 }

  condition:
    any of them
}