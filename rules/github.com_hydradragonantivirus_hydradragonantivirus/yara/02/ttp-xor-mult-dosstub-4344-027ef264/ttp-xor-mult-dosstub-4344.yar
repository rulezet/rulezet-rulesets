rule TTP_XOR_MULT_DOSStub_4344 {
  strings:
    $key_4344 = { 17 2c [2] 63 34 [2] 24 36 [2] 63 27 [2] 2d 2b [2] 21 21 [2] 36 2a [2] 2d 64 [2] 10 }

  condition:
    any of them
}