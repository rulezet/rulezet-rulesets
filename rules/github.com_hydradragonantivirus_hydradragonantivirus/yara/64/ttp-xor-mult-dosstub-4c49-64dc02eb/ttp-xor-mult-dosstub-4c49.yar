rule TTP_XOR_MULT_DOSStub_4c49 {
  strings:
    $key_4c49 = { 18 21 [2] 6c 39 [2] 2b 3b [2] 6c 2a [2] 22 26 [2] 2e 2c [2] 39 27 [2] 22 69 [2] 1f }

  condition:
    any of them
}