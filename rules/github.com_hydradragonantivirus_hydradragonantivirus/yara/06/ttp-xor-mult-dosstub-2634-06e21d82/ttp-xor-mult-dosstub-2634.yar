rule TTP_XOR_MULT_DOSStub_2634 {
  strings:
    $key_2634 = { 72 5c [2] 06 44 [2] 41 46 [2] 06 57 [2] 48 5b [2] 44 51 [2] 53 5a [2] 48 14 [2] 75 }

  condition:
    any of them
}