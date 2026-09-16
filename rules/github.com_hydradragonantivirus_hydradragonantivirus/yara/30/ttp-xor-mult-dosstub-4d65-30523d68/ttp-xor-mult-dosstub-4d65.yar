rule TTP_XOR_MULT_DOSStub_4d65 {
  strings:
    $key_4d65 = { 19 0d [2] 6d 15 [2] 2a 17 [2] 6d 06 [2] 23 0a [2] 2f 00 [2] 38 0b [2] 23 45 [2] 1e }

  condition:
    any of them
}