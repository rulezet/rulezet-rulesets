rule TTP_XOR_MULT_DOSStub_2665 {
  strings:
    $key_2665 = { 72 0d [2] 06 15 [2] 41 17 [2] 06 06 [2] 48 0a [2] 44 00 [2] 53 0b [2] 48 45 [2] 75 }

  condition:
    any of them
}