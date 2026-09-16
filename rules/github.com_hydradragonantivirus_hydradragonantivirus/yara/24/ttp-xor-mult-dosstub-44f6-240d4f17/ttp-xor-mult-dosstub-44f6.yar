rule TTP_XOR_MULT_DOSStub_44f6 {
  strings:
    $key_44f6 = { 10 9e [2] 64 86 [2] 23 84 [2] 64 95 [2] 2a 99 [2] 26 93 [2] 31 98 [2] 2a d6 [2] 17 }

  condition:
    any of them
}