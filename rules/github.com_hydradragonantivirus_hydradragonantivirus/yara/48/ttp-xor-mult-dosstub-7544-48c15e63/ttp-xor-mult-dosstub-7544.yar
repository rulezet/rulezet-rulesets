rule TTP_XOR_MULT_DOSStub_7544 {
  strings:
    $key_7544 = { 21 2c [2] 55 34 [2] 12 36 [2] 55 27 [2] 1b 2b [2] 17 21 [2] 00 2a [2] 1b 64 [2] 26 }

  condition:
    any of them
}