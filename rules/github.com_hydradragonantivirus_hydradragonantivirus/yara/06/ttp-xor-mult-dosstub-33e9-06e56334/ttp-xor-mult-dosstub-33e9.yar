rule TTP_XOR_MULT_DOSStub_33e9 {
  strings:
    $key_33e9 = { 67 81 [2] 13 99 [2] 54 9b [2] 13 8a [2] 5d 86 [2] 51 8c [2] 46 87 [2] 5d c9 [2] 60 }

  condition:
    any of them
}