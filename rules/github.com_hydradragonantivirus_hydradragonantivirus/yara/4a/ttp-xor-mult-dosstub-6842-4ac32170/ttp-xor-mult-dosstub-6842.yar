rule TTP_XOR_MULT_DOSStub_6842 {
  strings:
    $key_6842 = { 3c 2a [2] 48 32 [2] 0f 30 [2] 48 21 [2] 06 2d [2] 0a 27 [2] 1d 2c [2] 06 62 [2] 3b }

  condition:
    any of them
}