rule TTP_XOR_MULT_DOSStub_7f49 {
  strings:
    $key_7f49 = { 2b 21 [2] 5f 39 [2] 18 3b [2] 5f 2a [2] 11 26 [2] 1d 2c [2] 0a 27 [2] 11 69 [2] 2c }

  condition:
    any of them
}