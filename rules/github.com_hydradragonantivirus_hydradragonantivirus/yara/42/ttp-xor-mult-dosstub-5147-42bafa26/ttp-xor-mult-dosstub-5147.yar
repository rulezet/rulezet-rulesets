rule TTP_XOR_MULT_DOSStub_5147 {
  strings:
    $key_5147 = { 05 2f [2] 71 37 [2] 36 35 [2] 71 24 [2] 3f 28 [2] 33 22 [2] 24 29 [2] 3f 67 [2] 02 }

  condition:
    any of them
}