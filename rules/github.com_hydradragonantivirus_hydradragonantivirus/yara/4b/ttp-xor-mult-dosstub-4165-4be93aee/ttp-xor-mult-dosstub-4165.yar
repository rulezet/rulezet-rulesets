rule TTP_XOR_MULT_DOSStub_4165 {
  strings:
    $key_4165 = { 15 0d [2] 61 15 [2] 26 17 [2] 61 06 [2] 2f 0a [2] 23 00 [2] 34 0b [2] 2f 45 [2] 12 }

  condition:
    any of them
}