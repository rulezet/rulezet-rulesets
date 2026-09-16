rule TTP_XOR_MULT_DOSStub_5543 {
  strings:
    $key_5543 = { 01 2b [2] 75 33 [2] 32 31 [2] 75 20 [2] 3b 2c [2] 37 26 [2] 20 2d [2] 3b 63 [2] 06 }

  condition:
    any of them
}