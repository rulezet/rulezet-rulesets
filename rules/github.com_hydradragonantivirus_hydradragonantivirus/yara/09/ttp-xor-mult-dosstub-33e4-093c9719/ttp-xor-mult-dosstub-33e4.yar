rule TTP_XOR_MULT_DOSStub_33e4 {
  strings:
    $key_33e4 = { 67 8c [2] 13 94 [2] 54 96 [2] 13 87 [2] 5d 8b [2] 51 81 [2] 46 8a [2] 5d c4 [2] 60 }

  condition:
    any of them
}