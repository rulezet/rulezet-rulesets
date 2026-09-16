rule TTP_XOR_MULT_DOSStub_4449 {
  strings:
    $key_4449 = { 10 21 [2] 64 39 [2] 23 3b [2] 64 2a [2] 2a 26 [2] 26 2c [2] 31 27 [2] 2a 69 [2] 17 }

  condition:
    any of them
}