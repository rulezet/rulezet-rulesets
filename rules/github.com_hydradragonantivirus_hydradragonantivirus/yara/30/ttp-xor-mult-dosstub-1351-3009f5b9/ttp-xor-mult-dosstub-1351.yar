rule TTP_XOR_MULT_DOSStub_1351 {
  strings:
    $key_1351 = { 47 39 [2] 33 21 [2] 74 23 [2] 33 32 [2] 7d 3e [2] 71 34 [2] 66 3f [2] 7d 71 [2] 40 }

  condition:
    any of them
}