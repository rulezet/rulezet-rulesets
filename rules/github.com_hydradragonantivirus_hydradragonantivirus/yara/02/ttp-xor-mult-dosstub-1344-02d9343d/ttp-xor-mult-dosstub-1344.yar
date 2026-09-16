rule TTP_XOR_MULT_DOSStub_1344 {
  strings:
    $key_1344 = { 47 2c [2] 33 34 [2] 74 36 [2] 33 27 [2] 7d 2b [2] 71 21 [2] 66 2a [2] 7d 64 [2] 40 }

  condition:
    any of them
}