rule TTP_XOR_MULT_DOSStub_7d65 {
  strings:
    $key_7d65 = { 29 0d [2] 5d 15 [2] 1a 17 [2] 5d 06 [2] 13 0a [2] 1f 00 [2] 08 0b [2] 13 45 [2] 2e }

  condition:
    any of them
}