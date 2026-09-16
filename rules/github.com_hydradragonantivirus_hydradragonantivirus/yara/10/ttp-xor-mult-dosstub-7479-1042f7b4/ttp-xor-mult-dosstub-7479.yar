rule TTP_XOR_MULT_DOSStub_7479 {
  strings:
    $key_7479 = { 20 11 [2] 54 09 [2] 13 0b [2] 54 1a [2] 1a 16 [2] 16 1c [2] 01 17 [2] 1a 59 [2] 27 }

  condition:
    any of them
}