rule TTP_XOR_MULT_DOSStub_0434 {
  strings:
    $key_0434 = { 50 5c [2] 24 44 [2] 63 46 [2] 24 57 [2] 6a 5b [2] 66 51 [2] 71 5a [2] 6a 14 [2] 57 }

  condition:
    any of them
}