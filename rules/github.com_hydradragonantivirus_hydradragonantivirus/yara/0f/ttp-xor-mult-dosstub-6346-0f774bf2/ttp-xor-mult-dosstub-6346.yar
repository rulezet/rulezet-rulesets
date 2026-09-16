rule TTP_XOR_MULT_DOSStub_6346 {
  strings:
    $key_6346 = { 37 2e [2] 43 36 [2] 04 34 [2] 43 25 [2] 0d 29 [2] 01 23 [2] 16 28 [2] 0d 66 [2] 30 }

  condition:
    any of them
}