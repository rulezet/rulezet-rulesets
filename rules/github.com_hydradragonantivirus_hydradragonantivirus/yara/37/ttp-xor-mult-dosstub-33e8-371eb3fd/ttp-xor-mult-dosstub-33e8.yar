rule TTP_XOR_MULT_DOSStub_33e8 {
  strings:
    $key_33e8 = { 67 80 [2] 13 98 [2] 54 9a [2] 13 8b [2] 5d 87 [2] 51 8d [2] 46 86 [2] 5d c8 [2] 60 }

  condition:
    any of them
}