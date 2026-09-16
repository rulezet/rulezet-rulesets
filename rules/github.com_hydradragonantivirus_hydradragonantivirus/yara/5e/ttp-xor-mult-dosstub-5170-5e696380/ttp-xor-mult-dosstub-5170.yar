rule TTP_XOR_MULT_DOSStub_5170 {
  strings:
    $key_5170 = { 05 18 [2] 71 00 [2] 36 02 [2] 71 13 [2] 3f 1f [2] 33 15 [2] 24 1e [2] 3f 50 [2] 02 }

  condition:
    any of them
}