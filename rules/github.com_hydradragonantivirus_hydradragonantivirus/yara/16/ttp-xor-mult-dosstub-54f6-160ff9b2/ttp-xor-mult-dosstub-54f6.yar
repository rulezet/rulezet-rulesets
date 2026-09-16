rule TTP_XOR_MULT_DOSStub_54f6 {
  strings:
    $key_54f6 = { 00 9e [2] 74 86 [2] 33 84 [2] 74 95 [2] 3a 99 [2] 36 93 [2] 21 98 [2] 3a d6 [2] 07 }

  condition:
    any of them
}