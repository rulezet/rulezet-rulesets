rule TTP_XOR_MULT_DOSStub_1265 {
  strings:
    $key_1265 = { 46 0d [2] 32 15 [2] 75 17 [2] 32 06 [2] 7c 0a [2] 70 00 [2] 67 0b [2] 7c 45 [2] 41 }

  condition:
    any of them
}