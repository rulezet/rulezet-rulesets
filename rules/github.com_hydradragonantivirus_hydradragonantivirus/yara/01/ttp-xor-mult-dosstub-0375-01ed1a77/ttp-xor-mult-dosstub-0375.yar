rule TTP_XOR_MULT_DOSStub_0375 {
  strings:
    $key_0375 = { 57 1d [2] 23 05 [2] 64 07 [2] 23 16 [2] 6d 1a [2] 61 10 [2] 76 1b [2] 6d 55 [2] 50 }

  condition:
    any of them
}