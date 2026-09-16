rule TTP_XOR_MULT_DOSStub_7049 {
  strings:
    $key_7049 = { 24 21 [2] 50 39 [2] 17 3b [2] 50 2a [2] 1e 26 [2] 12 2c [2] 05 27 [2] 1e 69 [2] 23 }

  condition:
    any of them
}