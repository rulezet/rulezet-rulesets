rule TTP_XOR_MULT_DOSStub_1559 {
  strings:
    $key_1559 = { 41 31 [2] 35 29 [2] 72 2b [2] 35 3a [2] 7b 36 [2] 77 3c [2] 60 37 [2] 7b 79 [2] 46 }

  condition:
    any of them
}