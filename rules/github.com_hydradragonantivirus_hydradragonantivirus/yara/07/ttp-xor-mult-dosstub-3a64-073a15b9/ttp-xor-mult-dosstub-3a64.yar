rule TTP_XOR_MULT_DOSStub_3a64 {
  strings:
    $key_3a64 = { 6e 0c [2] 1a 14 [2] 5d 16 [2] 1a 07 [2] 54 0b [2] 58 01 [2] 4f 0a [2] 54 44 [2] 69 }

  condition:
    any of them
}