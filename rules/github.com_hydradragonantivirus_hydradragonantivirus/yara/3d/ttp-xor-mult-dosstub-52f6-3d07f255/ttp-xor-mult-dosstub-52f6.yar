rule TTP_XOR_MULT_DOSStub_52f6 {
  strings:
    $key_52f6 = { 06 9e [2] 72 86 [2] 35 84 [2] 72 95 [2] 3c 99 [2] 30 93 [2] 27 98 [2] 3c d6 [2] 01 }

  condition:
    any of them
}