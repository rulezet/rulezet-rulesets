rule TTP_XOR_MULT_DOSStub_42fb {
  strings:
    $key_42fb = { 16 93 [2] 62 8b [2] 25 89 [2] 62 98 [2] 2c 94 [2] 20 9e [2] 37 95 [2] 2c db [2] 11 }

  condition:
    any of them
}