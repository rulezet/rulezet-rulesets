rule TTP_XOR_MULT_DOSStub_0377 {
  strings:
    $key_0377 = { 57 1f [2] 23 07 [2] 64 05 [2] 23 14 [2] 6d 18 [2] 61 12 [2] 76 19 [2] 6d 57 [2] 50 }

  condition:
    any of them
}