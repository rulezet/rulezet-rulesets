rule TTP_XOR_MULT_DOSStub_4343 {
  strings:
    $key_4343 = { 17 2b [2] 63 33 [2] 24 31 [2] 63 20 [2] 2d 2c [2] 21 26 [2] 36 2d [2] 2d 63 [2] 10 }

  condition:
    any of them
}