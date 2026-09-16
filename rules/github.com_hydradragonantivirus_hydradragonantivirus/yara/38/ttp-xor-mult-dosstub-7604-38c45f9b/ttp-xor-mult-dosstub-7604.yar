rule TTP_XOR_MULT_DOSStub_7604 {
  strings:
    $key_7604 = { 22 6c [2] 56 74 [2] 11 76 [2] 56 67 [2] 18 6b [2] 14 61 [2] 03 6a [2] 18 24 [2] 25 }

  condition:
    any of them
}