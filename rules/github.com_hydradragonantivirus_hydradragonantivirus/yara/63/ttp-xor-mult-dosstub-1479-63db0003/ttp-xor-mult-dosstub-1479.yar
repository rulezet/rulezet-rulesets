rule TTP_XOR_MULT_DOSStub_1479 {
  strings:
    $key_1479 = { 40 11 [2] 34 09 [2] 73 0b [2] 34 1a [2] 7a 16 [2] 76 1c [2] 61 17 [2] 7a 59 [2] 47 }

  condition:
    any of them
}