rule TTP_XOR_MULT_DOSStub_41f6 {
  strings:
    $key_41f6 = { 15 9e [2] 61 86 [2] 26 84 [2] 61 95 [2] 2f 99 [2] 23 93 [2] 34 98 [2] 2f d6 [2] 12 }

  condition:
    any of them
}