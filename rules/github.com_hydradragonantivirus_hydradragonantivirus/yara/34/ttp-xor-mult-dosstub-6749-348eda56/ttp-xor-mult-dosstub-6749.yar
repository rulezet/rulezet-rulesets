rule TTP_XOR_MULT_DOSStub_6749 {
  strings:
    $key_6749 = { 33 21 [2] 47 39 [2] 00 3b [2] 47 2a [2] 09 26 [2] 05 2c [2] 12 27 [2] 09 69 [2] 34 }

  condition:
    any of them
}