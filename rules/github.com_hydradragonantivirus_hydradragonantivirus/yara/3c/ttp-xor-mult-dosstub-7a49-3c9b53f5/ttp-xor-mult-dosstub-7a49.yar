rule TTP_XOR_MULT_DOSStub_7a49 {
  strings:
    $key_7a49 = { 2e 21 [2] 5a 39 [2] 1d 3b [2] 5a 2a [2] 14 26 [2] 18 2c [2] 0f 27 [2] 14 69 [2] 29 }

  condition:
    any of them
}