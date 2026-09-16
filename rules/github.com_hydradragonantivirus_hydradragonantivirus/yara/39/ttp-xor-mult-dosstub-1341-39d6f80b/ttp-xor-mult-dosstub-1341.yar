rule TTP_XOR_MULT_DOSStub_1341 {
  strings:
    $key_1341 = { 47 29 [2] 33 31 [2] 74 33 [2] 33 22 [2] 7d 2e [2] 71 24 [2] 66 2f [2] 7d 61 [2] 40 }

  condition:
    any of them
}