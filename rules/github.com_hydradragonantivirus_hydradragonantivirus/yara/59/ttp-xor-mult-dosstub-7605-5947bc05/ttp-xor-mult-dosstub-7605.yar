rule TTP_XOR_MULT_DOSStub_7605 {
  strings:
    $key_7605 = { 22 6d [2] 56 75 [2] 11 77 [2] 56 66 [2] 18 6a [2] 14 60 [2] 03 6b [2] 18 25 [2] 25 }

  condition:
    any of them
}