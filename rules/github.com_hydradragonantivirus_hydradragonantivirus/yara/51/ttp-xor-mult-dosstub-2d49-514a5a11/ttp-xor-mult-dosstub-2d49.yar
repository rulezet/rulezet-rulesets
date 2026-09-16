rule TTP_XOR_MULT_DOSStub_2d49 {
  strings:
    $key_2d49 = { 79 21 [2] 0d 39 [2] 4a 3b [2] 0d 2a [2] 43 26 [2] 4f 2c [2] 58 27 [2] 43 69 [2] 7e }

  condition:
    any of them
}