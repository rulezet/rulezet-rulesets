rule TTP_XOR_MULT_DOSStub_42f9 {
  strings:
    $key_42f9 = { 16 91 [2] 62 89 [2] 25 8b [2] 62 9a [2] 2c 96 [2] 20 9c [2] 37 97 [2] 2c d9 [2] 11 }

  condition:
    any of them
}