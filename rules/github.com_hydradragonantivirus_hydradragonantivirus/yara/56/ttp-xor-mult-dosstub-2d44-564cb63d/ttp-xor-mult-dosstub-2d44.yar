rule TTP_XOR_MULT_DOSStub_2d44 {
  strings:
    $key_2d44 = { 79 2c [2] 0d 34 [2] 4a 36 [2] 0d 27 [2] 43 2b [2] 4f 21 [2] 58 2a [2] 43 64 [2] 7e }

  condition:
    any of them
}