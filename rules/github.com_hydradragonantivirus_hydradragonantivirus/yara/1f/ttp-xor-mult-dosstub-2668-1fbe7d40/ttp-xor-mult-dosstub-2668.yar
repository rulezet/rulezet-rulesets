rule TTP_XOR_MULT_DOSStub_2668 {
  strings:
    $key_2668 = { 72 00 [2] 06 18 [2] 41 1a [2] 06 0b [2] 48 07 [2] 44 0d [2] 53 06 [2] 48 48 [2] 75 }

  condition:
    any of them
}