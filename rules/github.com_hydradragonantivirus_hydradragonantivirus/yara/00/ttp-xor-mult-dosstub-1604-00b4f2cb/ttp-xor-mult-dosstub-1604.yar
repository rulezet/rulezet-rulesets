rule TTP_XOR_MULT_DOSStub_1604 {
  strings:
    $key_1604 = { 42 6c [2] 36 74 [2] 71 76 [2] 36 67 [2] 78 6b [2] 74 61 [2] 63 6a [2] 78 24 [2] 45 }

  condition:
    any of them
}