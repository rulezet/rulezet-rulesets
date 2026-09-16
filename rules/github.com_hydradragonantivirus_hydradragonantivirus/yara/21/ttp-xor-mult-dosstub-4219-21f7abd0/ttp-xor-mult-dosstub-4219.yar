rule TTP_XOR_MULT_DOSStub_4219 {
  strings:
    $key_4219 = { 16 71 [2] 62 69 [2] 25 6b [2] 62 7a [2] 2c 76 [2] 20 7c [2] 37 77 [2] 2c 39 [2] 11 }

  condition:
    any of them
}