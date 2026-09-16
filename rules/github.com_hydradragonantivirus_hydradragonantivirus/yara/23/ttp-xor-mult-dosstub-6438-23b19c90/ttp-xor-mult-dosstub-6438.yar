rule TTP_XOR_MULT_DOSStub_6438 {
  strings:
    $key_6438 = { 30 50 [2] 44 48 [2] 03 4a [2] 44 5b [2] 0a 57 [2] 06 5d [2] 11 56 [2] 0a 18 [2] 37 }

  condition:
    any of them
}