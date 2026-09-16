rule TTP_XOR_MULT_DOSStub_4608 {
  strings:
    $key_4608 = { 12 60 [2] 66 78 [2] 21 7a [2] 66 6b [2] 28 67 [2] 24 6d [2] 33 66 [2] 28 28 [2] 15 }

  condition:
    any of them
}