rule TTP_XOR_MULT_DOSStub_3375 {
  strings:
    $key_3375 = { 67 1d [2] 13 05 [2] 54 07 [2] 13 16 [2] 5d 1a [2] 51 10 [2] 46 1b [2] 5d 55 [2] 60 }

  condition:
    any of them
}