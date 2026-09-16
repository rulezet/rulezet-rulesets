rule TTP_XOR_MULT_DOSStub_1843 {
  strings:
    $key_1843 = { 4c 2b [2] 38 33 [2] 7f 31 [2] 38 20 [2] 76 2c [2] 7a 26 [2] 6d 2d [2] 76 63 [2] 4b }

  condition:
    any of them
}