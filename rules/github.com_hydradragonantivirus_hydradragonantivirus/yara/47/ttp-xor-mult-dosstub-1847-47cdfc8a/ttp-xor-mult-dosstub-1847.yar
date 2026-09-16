rule TTP_XOR_MULT_DOSStub_1847 {
  strings:
    $key_1847 = { 4c 2f [2] 38 37 [2] 7f 35 [2] 38 24 [2] 76 28 [2] 7a 22 [2] 6d 29 [2] 76 67 [2] 4b }

  condition:
    any of them
}