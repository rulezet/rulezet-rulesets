rule TTP_XOR_MULT_DOSStub_5146 {
  strings:
    $key_5146 = { 05 2e [2] 71 36 [2] 36 34 [2] 71 25 [2] 3f 29 [2] 33 23 [2] 24 28 [2] 3f 66 [2] 02 }

  condition:
    any of them
}