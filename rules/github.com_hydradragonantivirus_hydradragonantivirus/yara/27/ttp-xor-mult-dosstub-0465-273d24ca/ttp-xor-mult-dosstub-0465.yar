rule TTP_XOR_MULT_DOSStub_0465 {
  strings:
    $key_0465 = { 50 0d [2] 24 15 [2] 63 17 [2] 24 06 [2] 6a 0a [2] 66 00 [2] 71 0b [2] 6a 45 [2] 57 }

  condition:
    any of them
}