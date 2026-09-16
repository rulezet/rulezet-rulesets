rule TTP_XOR_MULT_DOSStub_4237 {
  strings:
    $key_4237 = { 16 5f [2] 62 47 [2] 25 45 [2] 62 54 [2] 2c 58 [2] 20 52 [2] 37 59 [2] 2c 17 [2] 11 }

  condition:
    any of them
}