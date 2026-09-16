rule TTP_XOR_MULT_DOSStub_4232 {
  strings:
    $key_4232 = { 16 5a [2] 62 42 [2] 25 40 [2] 62 51 [2] 2c 5d [2] 20 57 [2] 37 5c [2] 2c 12 [2] 11 }

  condition:
    any of them
}