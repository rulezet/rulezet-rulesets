rule TTP_XOR_MULT_DOSStub_4543 {
  strings:
    $key_4543 = { 11 2b [2] 65 33 [2] 22 31 [2] 65 20 [2] 2b 2c [2] 27 26 [2] 30 2d [2] 2b 63 [2] 16 }

  condition:
    any of them
}