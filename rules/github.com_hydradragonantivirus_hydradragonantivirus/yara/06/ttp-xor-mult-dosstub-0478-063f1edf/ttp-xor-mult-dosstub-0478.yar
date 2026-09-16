rule TTP_XOR_MULT_DOSStub_0478 {
  strings:
    $key_0478 = { 50 10 [2] 24 08 [2] 63 0a [2] 24 1b [2] 6a 17 [2] 66 1d [2] 71 16 [2] 6a 58 [2] 57 }

  condition:
    any of them
}