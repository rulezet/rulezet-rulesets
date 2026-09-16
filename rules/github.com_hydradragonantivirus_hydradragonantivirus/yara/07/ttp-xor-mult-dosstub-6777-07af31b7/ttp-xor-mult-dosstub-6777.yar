rule TTP_XOR_MULT_DOSStub_6777 {
  strings:
    $key_6777 = { 33 1f [2] 47 07 [2] 00 05 [2] 47 14 [2] 09 18 [2] 05 12 [2] 12 19 [2] 09 57 [2] 34 }

  condition:
    any of them
}