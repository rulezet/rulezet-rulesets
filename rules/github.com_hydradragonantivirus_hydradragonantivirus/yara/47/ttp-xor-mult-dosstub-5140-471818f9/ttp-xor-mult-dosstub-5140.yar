rule TTP_XOR_MULT_DOSStub_5140 {
  strings:
    $key_5140 = { 05 28 [2] 71 30 [2] 36 32 [2] 71 23 [2] 3f 2f [2] 33 25 [2] 24 2e [2] 3f 60 [2] 02 }

  condition:
    any of them
}