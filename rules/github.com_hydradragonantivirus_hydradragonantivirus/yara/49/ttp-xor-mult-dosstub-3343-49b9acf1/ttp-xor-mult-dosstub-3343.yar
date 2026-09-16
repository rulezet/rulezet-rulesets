rule TTP_XOR_MULT_DOSStub_3343 {
  strings:
    $key_3343 = { 67 2b [2] 13 33 [2] 54 31 [2] 13 20 [2] 5d 2c [2] 51 26 [2] 46 2d [2] 5d 63 [2] 60 }

  condition:
    any of them
}