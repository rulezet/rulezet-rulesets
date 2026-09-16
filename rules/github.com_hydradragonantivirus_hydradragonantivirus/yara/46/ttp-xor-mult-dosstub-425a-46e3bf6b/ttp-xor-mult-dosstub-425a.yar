rule TTP_XOR_MULT_DOSStub_425a {
  strings:
    $key_425a = { 16 32 [2] 62 2a [2] 25 28 [2] 62 39 [2] 2c 35 [2] 20 3f [2] 37 34 [2] 2c 7a [2] 11 }

  condition:
    any of them
}