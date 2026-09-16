rule TTP_XOR_MULT_DOSStub_2549 {
  strings:
    $key_2549 = { 71 21 [2] 05 39 [2] 42 3b [2] 05 2a [2] 4b 26 [2] 47 2c [2] 50 27 [2] 4b 69 [2] 76 }

  condition:
    any of them
}