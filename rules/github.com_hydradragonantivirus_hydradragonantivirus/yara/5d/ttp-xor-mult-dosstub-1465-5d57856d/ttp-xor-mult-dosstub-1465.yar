rule TTP_XOR_MULT_DOSStub_1465 {
  strings:
    $key_1465 = { 40 0d [2] 34 15 [2] 73 17 [2] 34 06 [2] 7a 0a [2] 76 00 [2] 61 0b [2] 7a 45 [2] 47 }

  condition:
    any of them
}