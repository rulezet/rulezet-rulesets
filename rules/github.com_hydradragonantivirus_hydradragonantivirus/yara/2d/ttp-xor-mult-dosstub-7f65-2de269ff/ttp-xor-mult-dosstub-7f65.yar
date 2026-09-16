rule TTP_XOR_MULT_DOSStub_7f65 {
  strings:
    $key_7f65 = { 2b 0d [2] 5f 15 [2] 18 17 [2] 5f 06 [2] 11 0a [2] 1d 00 [2] 0a 0b [2] 11 45 [2] 2c }

  condition:
    any of them
}