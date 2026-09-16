rule TTP_XOR_MULT_DOSStub_4360 {
  strings:
    $key_4360 = { 17 08 [2] 63 10 [2] 24 12 [2] 63 03 [2] 2d 0f [2] 21 05 [2] 36 0e [2] 2d 40 [2] 10 }

  condition:
    any of them
}