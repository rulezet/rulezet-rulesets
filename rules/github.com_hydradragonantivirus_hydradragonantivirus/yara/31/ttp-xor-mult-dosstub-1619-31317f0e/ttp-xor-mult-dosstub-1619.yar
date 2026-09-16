rule TTP_XOR_MULT_DOSStub_1619 {
  strings:
    $key_1619 = { 42 71 [2] 36 69 [2] 71 6b [2] 36 7a [2] 78 76 [2] 74 7c [2] 63 77 [2] 78 39 [2] 45 }

  condition:
    any of them
}