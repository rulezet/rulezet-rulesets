rule TTP_XOR_MULT_DOSStub_4311 {
  strings:
    $key_4311 = { 17 79 [2] 63 61 [2] 24 63 [2] 63 72 [2] 2d 7e [2] 21 74 [2] 36 7f [2] 2d 31 [2] 10 }

  condition:
    any of them
}