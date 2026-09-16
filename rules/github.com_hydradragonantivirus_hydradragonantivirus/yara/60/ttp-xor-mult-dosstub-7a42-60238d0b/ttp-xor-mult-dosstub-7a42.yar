rule TTP_XOR_MULT_DOSStub_7a42 {
  strings:
    $key_7a42 = { 2e 2a [2] 5a 32 [2] 1d 30 [2] 5a 21 [2] 14 2d [2] 18 27 [2] 0f 2c [2] 14 62 [2] 29 }

  condition:
    any of them
}