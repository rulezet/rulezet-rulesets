rule TTP_XOR_MULT_DOSStub_5415 {
  strings:
    $key_5415 = { 00 7d [2] 74 65 [2] 33 67 [2] 74 76 [2] 3a 7a [2] 36 70 [2] 21 7b [2] 3a 35 [2] 07 }

  condition:
    any of them
}