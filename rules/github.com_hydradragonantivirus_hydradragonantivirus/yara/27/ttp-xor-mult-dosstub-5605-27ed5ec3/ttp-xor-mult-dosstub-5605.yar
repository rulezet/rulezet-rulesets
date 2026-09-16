rule TTP_XOR_MULT_DOSStub_5605 {
  strings:
    $key_5605 = { 02 6d [2] 76 75 [2] 31 77 [2] 76 66 [2] 38 6a [2] 34 60 [2] 23 6b [2] 38 25 [2] 05 }

  condition:
    any of them
}