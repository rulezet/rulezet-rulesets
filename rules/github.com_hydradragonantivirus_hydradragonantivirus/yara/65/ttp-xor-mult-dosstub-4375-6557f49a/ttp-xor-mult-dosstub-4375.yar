rule TTP_XOR_MULT_DOSStub_4375 {
  strings:
    $key_4375 = { 17 1d [2] 63 05 [2] 24 07 [2] 63 16 [2] 2d 1a [2] 21 10 [2] 36 1b [2] 2d 55 [2] 10 }

  condition:
    any of them
}