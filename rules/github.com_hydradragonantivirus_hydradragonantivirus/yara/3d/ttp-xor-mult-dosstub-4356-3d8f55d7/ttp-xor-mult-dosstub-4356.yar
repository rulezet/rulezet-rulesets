rule TTP_XOR_MULT_DOSStub_4356 {
  strings:
    $key_4356 = { 17 3e [2] 63 26 [2] 24 24 [2] 63 35 [2] 2d 39 [2] 21 33 [2] 36 38 [2] 2d 76 [2] 10 }

  condition:
    any of them
}