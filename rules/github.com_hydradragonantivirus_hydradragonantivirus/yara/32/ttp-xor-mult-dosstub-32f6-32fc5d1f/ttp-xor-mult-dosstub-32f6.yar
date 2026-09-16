rule TTP_XOR_MULT_DOSStub_32f6 {
  strings:
    $key_32f6 = { 66 9e [2] 12 86 [2] 55 84 [2] 12 95 [2] 5c 99 [2] 50 93 [2] 47 98 [2] 5c d6 [2] 61 }

  condition:
    any of them
}