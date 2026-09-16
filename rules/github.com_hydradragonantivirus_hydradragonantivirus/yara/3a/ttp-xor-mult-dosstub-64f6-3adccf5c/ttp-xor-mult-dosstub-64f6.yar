rule TTP_XOR_MULT_DOSStub_64f6 {
  strings:
    $key_64f6 = { 30 9e [2] 44 86 [2] 03 84 [2] 44 95 [2] 0a 99 [2] 06 93 [2] 11 98 [2] 0a d6 [2] 37 }

  condition:
    any of them
}