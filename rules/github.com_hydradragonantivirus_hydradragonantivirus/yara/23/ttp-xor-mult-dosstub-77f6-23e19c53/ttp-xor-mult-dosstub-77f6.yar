rule TTP_XOR_MULT_DOSStub_77f6 {
  strings:
    $key_77f6 = { 23 9e [2] 57 86 [2] 10 84 [2] 57 95 [2] 19 99 [2] 15 93 [2] 02 98 [2] 19 d6 [2] 24 }

  condition:
    any of them
}