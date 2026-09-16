rule TTP_XOR_MULT_DOSStub_5d65 {
  strings:
    $key_5d65 = { 09 0d [2] 7d 15 [2] 3a 17 [2] 7d 06 [2] 33 0a [2] 3f 00 [2] 28 0b [2] 33 45 [2] 0e }

  condition:
    any of them
}