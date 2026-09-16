rule TTP_XOR_MULT_DOSStub_4619 {
  strings:
    $key_4619 = { 12 71 [2] 66 69 [2] 21 6b [2] 66 7a [2] 28 76 [2] 24 7c [2] 33 77 [2] 28 39 [2] 15 }

  condition:
    any of them
}