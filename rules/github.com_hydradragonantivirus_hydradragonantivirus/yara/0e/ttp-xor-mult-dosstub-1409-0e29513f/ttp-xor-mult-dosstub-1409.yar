rule TTP_XOR_MULT_DOSStub_1409 {
  strings:
    $key_1409 = { 40 61 [2] 34 79 [2] 73 7b [2] 34 6a [2] 7a 66 [2] 76 6c [2] 61 67 [2] 7a 29 [2] 47 }

  condition:
    any of them
}