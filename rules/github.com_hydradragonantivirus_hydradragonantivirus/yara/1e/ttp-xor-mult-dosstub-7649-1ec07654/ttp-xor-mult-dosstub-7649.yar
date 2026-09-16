rule TTP_XOR_MULT_DOSStub_7649 {
  strings:
    $key_7649 = { 22 21 [2] 56 39 [2] 11 3b [2] 56 2a [2] 18 26 [2] 14 2c [2] 03 27 [2] 18 69 [2] 25 }

  condition:
    any of them
}