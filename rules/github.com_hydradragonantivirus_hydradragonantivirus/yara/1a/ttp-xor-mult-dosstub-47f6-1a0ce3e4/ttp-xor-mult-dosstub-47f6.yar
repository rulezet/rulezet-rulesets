rule TTP_XOR_MULT_DOSStub_47f6 {
  strings:
    $key_47f6 = { 13 9e [2] 67 86 [2] 20 84 [2] 67 95 [2] 29 99 [2] 25 93 [2] 32 98 [2] 29 d6 [2] 14 }

  condition:
    any of them
}