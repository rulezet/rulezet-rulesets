rule TTP_XOR_MULT_DOSStub_5249 {
  strings:
    $key_5249 = { 06 21 [2] 72 39 [2] 35 3b [2] 72 2a [2] 3c 26 [2] 30 2c [2] 27 27 [2] 3c 69 [2] 01 }

  condition:
    any of them
}