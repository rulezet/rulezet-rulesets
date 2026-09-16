rule TTP_XOR_MULT_DOSStub_54f5 {
  strings:
    $key_54f5 = { 00 9d [2] 74 85 [2] 33 87 [2] 74 96 [2] 3a 9a [2] 36 90 [2] 21 9b [2] 3a d5 [2] 07 }

  condition:
    any of them
}