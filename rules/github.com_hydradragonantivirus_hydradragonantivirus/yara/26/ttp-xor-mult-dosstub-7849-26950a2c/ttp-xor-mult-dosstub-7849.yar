rule TTP_XOR_MULT_DOSStub_7849 {
  strings:
    $key_7849 = { 2c 21 [2] 58 39 [2] 1f 3b [2] 58 2a [2] 16 26 [2] 1a 2c [2] 0d 27 [2] 16 69 [2] 2b }

  condition:
    any of them
}