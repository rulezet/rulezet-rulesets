rule TTP_XOR_MULT_DOSStub_3a49 {
  strings:
    $key_3a49 = { 6e 21 [2] 1a 39 [2] 5d 3b [2] 1a 2a [2] 54 26 [2] 58 2c [2] 4f 27 [2] 54 69 [2] 69 }

  condition:
    any of them
}