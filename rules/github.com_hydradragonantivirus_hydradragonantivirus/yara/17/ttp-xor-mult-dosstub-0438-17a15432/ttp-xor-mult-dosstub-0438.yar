rule TTP_XOR_MULT_DOSStub_0438 {
  strings:
    $key_0438 = { 50 50 [2] 24 48 [2] 63 4a [2] 24 5b [2] 6a 57 [2] 66 5d [2] 71 56 [2] 6a 18 [2] 57 }

  condition:
    any of them
}