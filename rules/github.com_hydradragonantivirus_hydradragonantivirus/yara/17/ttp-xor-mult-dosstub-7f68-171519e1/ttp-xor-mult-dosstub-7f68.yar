rule TTP_XOR_MULT_DOSStub_7f68 {
  strings:
    $key_7f68 = { 2b 00 [2] 5f 18 [2] 18 1a [2] 5f 0b [2] 11 07 [2] 1d 0d [2] 0a 06 [2] 11 48 [2] 2c }

  condition:
    any of them
}