rule TTP_XOR_MULT_DOSStub_4f68 {
  strings:
    $key_4f68 = { 1b 00 [2] 6f 18 [2] 28 1a [2] 6f 0b [2] 21 07 [2] 2d 0d [2] 3a 06 [2] 21 48 [2] 1c }

  condition:
    any of them
}