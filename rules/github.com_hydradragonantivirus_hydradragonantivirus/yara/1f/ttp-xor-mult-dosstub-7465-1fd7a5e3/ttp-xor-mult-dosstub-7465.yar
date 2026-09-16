rule TTP_XOR_MULT_DOSStub_7465 {
  strings:
    $key_7465 = { 20 0d [2] 54 15 [2] 13 17 [2] 54 06 [2] 1a 0a [2] 16 00 [2] 01 0b [2] 1a 45 [2] 27 }

  condition:
    any of them
}