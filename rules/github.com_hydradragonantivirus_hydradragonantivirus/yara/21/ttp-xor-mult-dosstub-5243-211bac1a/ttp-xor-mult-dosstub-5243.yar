rule TTP_XOR_MULT_DOSStub_5243 {
  strings:
    $key_5243 = { 06 2b [2] 72 33 [2] 35 31 [2] 72 20 [2] 3c 2c [2] 30 26 [2] 27 2d [2] 3c 63 [2] 01 }

  condition:
    any of them
}