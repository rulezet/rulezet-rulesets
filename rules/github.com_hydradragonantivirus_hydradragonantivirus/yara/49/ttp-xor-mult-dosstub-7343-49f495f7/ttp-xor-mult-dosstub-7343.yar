rule TTP_XOR_MULT_DOSStub_7343 {
  strings:
    $key_7343 = { 27 2b [2] 53 33 [2] 14 31 [2] 53 20 [2] 1d 2c [2] 11 26 [2] 06 2d [2] 1d 63 [2] 20 }

  condition:
    any of them
}