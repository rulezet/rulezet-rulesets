rule TTP_XOR_MULT_DOSStub_1849 {
  strings:
    $key_1849 = { 4c 21 [2] 38 39 [2] 7f 3b [2] 38 2a [2] 76 26 [2] 7a 2c [2] 6d 27 [2] 76 69 [2] 4b }

  condition:
    any of them
}