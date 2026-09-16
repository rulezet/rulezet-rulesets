rule TTP_XOR_MULT_DOSStub_54f7 {
  strings:
    $key_54f7 = { 00 9f [2] 74 87 [2] 33 85 [2] 74 94 [2] 3a 98 [2] 36 92 [2] 21 99 [2] 3a d7 [2] 07 }

  condition:
    any of them
}