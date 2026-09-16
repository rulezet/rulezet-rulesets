rule TTP_XOR_MULT_DOSStub_4238 {
  strings:
    $key_4238 = { 16 50 [2] 62 48 [2] 25 4a [2] 62 5b [2] 2c 57 [2] 20 5d [2] 37 56 [2] 2c 18 [2] 11 }

  condition:
    any of them
}