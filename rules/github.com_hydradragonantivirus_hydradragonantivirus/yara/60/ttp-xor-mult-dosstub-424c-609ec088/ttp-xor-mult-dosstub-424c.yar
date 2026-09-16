rule TTP_XOR_MULT_DOSStub_424c {
  strings:
    $key_424c = { 16 24 [2] 62 3c [2] 25 3e [2] 62 2f [2] 2c 23 [2] 20 29 [2] 37 22 [2] 2c 6c [2] 11 }

  condition:
    any of them
}