rule TTP_XOR_MULT_DOSStub_6277 {
  strings:
    $key_6277 = { 36 1f [2] 42 07 [2] 05 05 [2] 42 14 [2] 0c 18 [2] 00 12 [2] 17 19 [2] 0c 57 [2] 31 }

  condition:
    any of them
}