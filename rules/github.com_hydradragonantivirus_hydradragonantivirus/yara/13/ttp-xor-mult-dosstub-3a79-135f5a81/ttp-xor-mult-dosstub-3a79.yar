rule TTP_XOR_MULT_DOSStub_3a79 {
  strings:
    $key_3a79 = { 6e 11 [2] 1a 09 [2] 5d 0b [2] 1a 1a [2] 54 16 [2] 58 1c [2] 4f 17 [2] 54 59 [2] 69 }

  condition:
    any of them
}