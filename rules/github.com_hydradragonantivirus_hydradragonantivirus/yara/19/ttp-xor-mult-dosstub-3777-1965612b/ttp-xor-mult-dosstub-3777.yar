rule TTP_XOR_MULT_DOSStub_3777 {
  strings:
    $key_3777 = { 63 1f [2] 17 07 [2] 50 05 [2] 17 14 [2] 59 18 [2] 55 12 [2] 42 19 [2] 59 57 [2] 64 }

  condition:
    any of them
}