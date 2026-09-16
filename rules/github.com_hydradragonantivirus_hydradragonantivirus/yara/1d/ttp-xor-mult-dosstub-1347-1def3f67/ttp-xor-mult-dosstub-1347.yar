rule TTP_XOR_MULT_DOSStub_1347 {
  strings:
    $key_1347 = { 47 2f [2] 33 37 [2] 74 35 [2] 33 24 [2] 7d 28 [2] 71 22 [2] 66 29 [2] 7d 67 [2] 40 }

  condition:
    any of them
}