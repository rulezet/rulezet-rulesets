rule TTP_XOR_MULT_DOSStub_1249 {
  strings:
    $key_1249 = { 46 21 [2] 32 39 [2] 75 3b [2] 32 2a [2] 7c 26 [2] 70 2c [2] 67 27 [2] 7c 69 [2] 41 }

  condition:
    any of them
}