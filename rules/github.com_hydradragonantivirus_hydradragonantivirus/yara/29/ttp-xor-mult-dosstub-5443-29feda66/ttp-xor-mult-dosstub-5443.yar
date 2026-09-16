rule TTP_XOR_MULT_DOSStub_5443 {
  strings:
    $key_5443 = { 00 2b [2] 74 33 [2] 33 31 [2] 74 20 [2] 3a 2c [2] 36 26 [2] 21 2d [2] 3a 63 [2] 07 }

  condition:
    any of them
}