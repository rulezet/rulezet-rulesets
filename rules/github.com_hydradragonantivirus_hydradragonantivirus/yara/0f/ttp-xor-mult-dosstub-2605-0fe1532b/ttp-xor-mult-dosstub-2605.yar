rule TTP_XOR_MULT_DOSStub_2605 {
  strings:
    $key_2605 = { 72 6d [2] 06 75 [2] 41 77 [2] 06 66 [2] 48 6a [2] 44 60 [2] 53 6b [2] 48 25 [2] 75 }

  condition:
    any of them
}