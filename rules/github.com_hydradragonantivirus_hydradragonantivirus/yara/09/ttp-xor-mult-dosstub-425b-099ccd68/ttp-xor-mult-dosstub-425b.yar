rule TTP_XOR_MULT_DOSStub_425b {
  strings:
    $key_425b = { 16 33 [2] 62 2b [2] 25 29 [2] 62 38 [2] 2c 34 [2] 20 3e [2] 37 35 [2] 2c 7b [2] 11 }

  condition:
    any of them
}