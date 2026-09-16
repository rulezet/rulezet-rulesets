rule TTP_XOR_MULT_DOSStub_0370 {
  strings:
    $key_0370 = { 57 18 [2] 23 00 [2] 64 02 [2] 23 13 [2] 6d 1f [2] 61 15 [2] 76 1e [2] 6d 50 [2] 50 }

  condition:
    any of them
}