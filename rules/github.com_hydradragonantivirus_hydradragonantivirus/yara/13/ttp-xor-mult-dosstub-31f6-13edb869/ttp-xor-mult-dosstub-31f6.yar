rule TTP_XOR_MULT_DOSStub_31f6 {
  strings:
    $key_31f6 = { 65 9e [2] 11 86 [2] 56 84 [2] 11 95 [2] 5f 99 [2] 53 93 [2] 44 98 [2] 5f d6 [2] 62 }

  condition:
    any of them
}