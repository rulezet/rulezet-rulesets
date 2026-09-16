rule TTP_XOR_MULT_DOSStub_0343 {
  strings:
    $key_0343 = { 57 2b [2] 23 33 [2] 64 31 [2] 23 20 [2] 6d 2c [2] 61 26 [2] 76 2d [2] 6d 63 [2] 50 }

  condition:
    any of them
}