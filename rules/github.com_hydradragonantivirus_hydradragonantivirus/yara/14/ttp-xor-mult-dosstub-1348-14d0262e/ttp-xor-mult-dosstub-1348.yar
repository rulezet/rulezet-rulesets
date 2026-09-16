rule TTP_XOR_MULT_DOSStub_1348 {
  strings:
    $key_1348 = { 47 20 [2] 33 38 [2] 74 3a [2] 33 2b [2] 7d 27 [2] 71 2d [2] 66 26 [2] 7d 68 [2] 40 }

  condition:
    any of them
}