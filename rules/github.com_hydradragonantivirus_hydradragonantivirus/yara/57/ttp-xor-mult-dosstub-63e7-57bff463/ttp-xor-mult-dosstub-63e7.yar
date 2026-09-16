rule TTP_XOR_MULT_DOSStub_63e7 {
  strings:
    $key_63e7 = { 37 8f [2] 43 97 [2] 04 95 [2] 43 84 [2] 0d 88 [2] 01 82 [2] 16 89 [2] 0d c7 [2] 30 }

  condition:
    any of them
}