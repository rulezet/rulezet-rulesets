rule TTP_XOR_MULT_DOSStub_1434 {
  strings:
    $key_1434 = { 40 5c [2] 34 44 [2] 73 46 [2] 34 57 [2] 7a 5b [2] 76 51 [2] 61 5a [2] 7a 14 [2] 47 }

  condition:
    any of them
}