rule TTP_XOR_MULT_DOSStub_07f6 {
  strings:
    $key_07f6 = { 53 9e [2] 27 86 [2] 60 84 [2] 27 95 [2] 69 99 [2] 65 93 [2] 72 98 [2] 69 d6 [2] 54 }

  condition:
    any of them
}