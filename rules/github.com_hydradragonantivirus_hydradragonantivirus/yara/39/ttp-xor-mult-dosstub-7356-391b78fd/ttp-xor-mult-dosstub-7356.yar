rule TTP_XOR_MULT_DOSStub_7356 {
  strings:
    $key_7356 = { 27 3e [2] 53 26 [2] 14 24 [2] 53 35 [2] 1d 39 [2] 11 33 [2] 06 38 [2] 1d 76 [2] 20 }

  condition:
    any of them
}