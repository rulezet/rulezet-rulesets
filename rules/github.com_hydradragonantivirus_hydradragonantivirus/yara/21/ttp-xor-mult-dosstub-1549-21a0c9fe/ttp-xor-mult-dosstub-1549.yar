rule TTP_XOR_MULT_DOSStub_1549 {
  strings:
    $key_1549 = { 41 21 [2] 35 39 [2] 72 3b [2] 35 2a [2] 7b 26 [2] 77 2c [2] 60 27 [2] 7b 69 [2] 46 }

  condition:
    any of them
}