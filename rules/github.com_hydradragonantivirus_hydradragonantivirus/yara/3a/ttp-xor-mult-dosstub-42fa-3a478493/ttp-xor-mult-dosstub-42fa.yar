rule TTP_XOR_MULT_DOSStub_42fa {
  strings:
    $key_42fa = { 16 92 [2] 62 8a [2] 25 88 [2] 62 99 [2] 2c 95 [2] 20 9f [2] 37 94 [2] 2c da [2] 11 }

  condition:
    any of them
}