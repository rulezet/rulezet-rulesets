rule TTP_XOR_MULT_DOSStub_4565 {
  strings:
    $key_4565 = { 11 0d [2] 65 15 [2] 22 17 [2] 65 06 [2] 2b 0a [2] 27 00 [2] 30 0b [2] 2b 45 [2] 16 }

  condition:
    any of them
}