rule TTP_XOR_MULT_DOSStub_424b {
  strings:
    $key_424b = { 16 23 [2] 62 3b [2] 25 39 [2] 62 28 [2] 2c 24 [2] 20 2e [2] 37 25 [2] 2c 6b [2] 11 }

  condition:
    any of them
}