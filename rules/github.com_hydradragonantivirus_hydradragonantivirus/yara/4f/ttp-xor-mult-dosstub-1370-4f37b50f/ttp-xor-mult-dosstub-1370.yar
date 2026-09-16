rule TTP_XOR_MULT_DOSStub_1370 {
  strings:
    $key_1370 = { 47 18 [2] 33 00 [2] 74 02 [2] 33 13 [2] 7d 1f [2] 71 15 [2] 66 1e [2] 7d 50 [2] 40 }

  condition:
    any of them
}