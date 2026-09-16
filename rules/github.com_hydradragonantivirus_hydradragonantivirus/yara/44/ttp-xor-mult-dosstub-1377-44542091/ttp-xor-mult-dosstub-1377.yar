rule TTP_XOR_MULT_DOSStub_1377 {
  strings:
    $key_1377 = { 47 1f [2] 33 07 [2] 74 05 [2] 33 14 [2] 7d 18 [2] 71 12 [2] 66 19 [2] 7d 57 [2] 40 }

  condition:
    any of them
}