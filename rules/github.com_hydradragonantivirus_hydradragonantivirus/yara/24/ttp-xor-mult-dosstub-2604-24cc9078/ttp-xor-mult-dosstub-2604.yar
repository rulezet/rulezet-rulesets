rule TTP_XOR_MULT_DOSStub_2604 {
  strings:
    $key_2604 = { 72 6c [2] 06 74 [2] 41 76 [2] 06 67 [2] 48 6b [2] 44 61 [2] 53 6a [2] 48 24 [2] 75 }

  condition:
    any of them
}