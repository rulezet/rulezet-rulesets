rule TTP_XOR_MULT_DOSStub_7c49 {
  strings:
    $key_7c49 = { 28 21 [2] 5c 39 [2] 1b 3b [2] 5c 2a [2] 12 26 [2] 1e 2c [2] 09 27 [2] 12 69 [2] 2f }

  condition:
    any of them
}