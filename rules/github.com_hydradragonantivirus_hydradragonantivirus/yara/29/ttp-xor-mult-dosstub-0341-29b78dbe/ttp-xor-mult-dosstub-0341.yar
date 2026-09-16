rule TTP_XOR_MULT_DOSStub_0341 {
  strings:
    $key_0341 = { 57 29 [2] 23 31 [2] 64 33 [2] 23 22 [2] 6d 2e [2] 61 24 [2] 76 2f [2] 6d 61 [2] 50 }

  condition:
    any of them
}