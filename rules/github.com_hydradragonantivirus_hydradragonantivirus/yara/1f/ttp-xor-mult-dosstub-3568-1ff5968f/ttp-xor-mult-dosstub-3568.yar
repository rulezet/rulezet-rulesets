rule TTP_XOR_MULT_DOSStub_3568 {
  strings:
    $key_3568 = { 61 00 [2] 15 18 [2] 52 1a [2] 15 0b [2] 5b 07 [2] 57 0d [2] 40 06 [2] 5b 48 [2] 66 }

  condition:
    any of them
}