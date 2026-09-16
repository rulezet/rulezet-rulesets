rule TTP_XOR_MULT_DOSStub_5049 {
  strings:
    $key_5049 = { 04 21 [2] 70 39 [2] 37 3b [2] 70 2a [2] 3e 26 [2] 32 2c [2] 25 27 [2] 3e 69 [2] 03 }

  condition:
    any of them
}