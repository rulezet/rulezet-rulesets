rule TTP_XOR_MULT_DOSStub_0474 {
  strings:
    $key_0474 = { 50 1c [2] 24 04 [2] 63 06 [2] 24 17 [2] 6a 1b [2] 66 11 [2] 71 1a [2] 6a 54 [2] 57 }

  condition:
    any of them
}