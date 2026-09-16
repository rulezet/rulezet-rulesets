rule TTP_XOR_MULT_DOSStub_3374 {
  strings:
    $key_3374 = { 67 1c [2] 13 04 [2] 54 06 [2] 13 17 [2] 5d 1b [2] 51 11 [2] 46 1a [2] 5d 54 [2] 60 }

  condition:
    any of them
}