rule TTP_XOR_MULT_DOSStub_75f5 {
  strings:
    $key_75f5 = { 21 9d [2] 55 85 [2] 12 87 [2] 55 96 [2] 1b 9a [2] 17 90 [2] 00 9b [2] 1b d5 [2] 26 }

  condition:
    any of them
}