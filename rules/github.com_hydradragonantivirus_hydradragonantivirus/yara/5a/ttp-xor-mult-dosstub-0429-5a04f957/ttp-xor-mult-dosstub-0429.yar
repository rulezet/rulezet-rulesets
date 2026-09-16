rule TTP_XOR_MULT_DOSStub_0429 {
  strings:
    $key_0429 = { 50 41 [2] 24 59 [2] 63 5b [2] 24 4a [2] 6a 46 [2] 66 4c [2] 71 47 [2] 6a 09 [2] 57 }

  condition:
    any of them
}