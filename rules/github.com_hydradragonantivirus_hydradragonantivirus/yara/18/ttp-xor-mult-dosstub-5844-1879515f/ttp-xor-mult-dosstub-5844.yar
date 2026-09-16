rule TTP_XOR_MULT_DOSStub_5844 {
  strings:
    $key_5844 = { 0c 2c [2] 78 34 [2] 3f 36 [2] 78 27 [2] 36 2b [2] 3a 21 [2] 2d 2a [2] 36 64 [2] 0b }

  condition:
    any of them
}