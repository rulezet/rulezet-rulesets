rule TTP_XOR_MULT_DOSStub_0479 {
  strings:
    $key_0479 = { 50 11 [2] 24 09 [2] 63 0b [2] 24 1a [2] 6a 16 [2] 66 1c [2] 71 17 [2] 6a 59 [2] 57 }

  condition:
    any of them
}