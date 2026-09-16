rule TTP_XOR_MULT_DOSStub_75f7 {
  strings:
    $key_75f7 = { 21 9f [2] 55 87 [2] 12 85 [2] 55 94 [2] 1b 98 [2] 17 92 [2] 00 99 [2] 1b d7 [2] 26 }

  condition:
    any of them
}