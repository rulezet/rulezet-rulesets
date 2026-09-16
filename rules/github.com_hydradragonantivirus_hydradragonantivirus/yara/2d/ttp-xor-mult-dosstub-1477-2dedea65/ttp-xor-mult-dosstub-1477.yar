rule TTP_XOR_MULT_DOSStub_1477 {
  strings:
    $key_1477 = { 40 1f [2] 34 07 [2] 73 05 [2] 34 14 [2] 7a 18 [2] 76 12 [2] 61 19 [2] 7a 57 [2] 47 }

  condition:
    any of them
}