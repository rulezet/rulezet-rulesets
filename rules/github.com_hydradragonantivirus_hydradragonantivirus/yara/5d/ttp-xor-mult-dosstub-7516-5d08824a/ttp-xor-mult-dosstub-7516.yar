rule TTP_XOR_MULT_DOSStub_7516 {
  strings:
    $key_7516 = { 21 7e [2] 55 66 [2] 12 64 [2] 55 75 [2] 1b 79 [2] 17 73 [2] 00 78 [2] 1b 36 [2] 26 }

  condition:
    any of them
}