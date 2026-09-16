rule TTP_XOR_MULT_DOSStub_1665 {
  strings:
    $key_1665 = { 42 0d [2] 36 15 [2] 71 17 [2] 36 06 [2] 78 0a [2] 74 00 [2] 63 0b [2] 78 45 [2] 45 }

  condition:
    any of them
}