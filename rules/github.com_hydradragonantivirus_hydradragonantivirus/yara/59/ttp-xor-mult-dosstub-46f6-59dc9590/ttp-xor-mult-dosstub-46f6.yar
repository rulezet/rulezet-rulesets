rule TTP_XOR_MULT_DOSStub_46f6 {
  strings:
    $key_46f6 = { 12 9e [2] 66 86 [2] 21 84 [2] 66 95 [2] 28 99 [2] 24 93 [2] 33 98 [2] 28 d6 [2] 15 }

  condition:
    any of them
}