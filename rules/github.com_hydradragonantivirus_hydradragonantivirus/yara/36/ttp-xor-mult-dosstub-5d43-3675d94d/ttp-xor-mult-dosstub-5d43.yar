rule TTP_XOR_MULT_DOSStub_5d43 {
  strings:
    $key_5d43 = { 09 2b [2] 7d 33 [2] 3a 31 [2] 7d 20 [2] 33 2c [2] 3f 26 [2] 28 2d [2] 33 63 [2] 0e }

  condition:
    any of them
}