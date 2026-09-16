rule TTP_XOR_MULT_DOSStub_6d42 {
  strings:
    $key_6d42 = { 39 2a [2] 4d 32 [2] 0a 30 [2] 4d 21 [2] 03 2d [2] 0f 27 [2] 18 2c [2] 03 62 [2] 3e }

  condition:
    any of them
}