rule TTP_XOR_MULT_DOSStub_1743 {
  strings:
    $key_1743 = { 43 2b [2] 37 33 [2] 70 31 [2] 37 20 [2] 79 2c [2] 75 26 [2] 62 2d [2] 79 63 [2] 44 }

  condition:
    any of them
}