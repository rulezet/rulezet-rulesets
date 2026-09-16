rule TTP_XOR_MULT_DOSStub_4273 {
  strings:
    $key_4273 = { 16 1b [2] 62 03 [2] 25 01 [2] 62 10 [2] 2c 1c [2] 20 16 [2] 37 1d [2] 2c 53 [2] 11 }

  condition:
    any of them
}