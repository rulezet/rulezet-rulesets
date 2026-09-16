rule TTP_XOR_MULT_DOSStub_21f6 {
  strings:
    $key_21f6 = { 75 9e [2] 01 86 [2] 46 84 [2] 01 95 [2] 4f 99 [2] 43 93 [2] 54 98 [2] 4f d6 [2] 72 }

  condition:
    any of them
}