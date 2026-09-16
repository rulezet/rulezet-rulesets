rule TTP_XOR_MULT_DOSStub_0463 {
  strings:
    $key_0463 = { 50 0b [2] 24 13 [2] 63 11 [2] 24 00 [2] 6a 0c [2] 66 06 [2] 71 0d [2] 6a 43 [2] 57 }

  condition:
    any of them
}