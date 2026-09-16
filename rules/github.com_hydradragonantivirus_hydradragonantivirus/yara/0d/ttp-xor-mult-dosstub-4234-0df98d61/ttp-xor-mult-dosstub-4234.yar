rule TTP_XOR_MULT_DOSStub_4234 {
  strings:
    $key_4234 = { 16 5c [2] 62 44 [2] 25 46 [2] 62 57 [2] 2c 5b [2] 20 51 [2] 37 5a [2] 2c 14 [2] 11 }

  condition:
    any of them
}