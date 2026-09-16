rule TTP_XOR_MULT_DOSStub_7634 {
  strings:
    $key_7634 = { 22 5c [2] 56 44 [2] 11 46 [2] 56 57 [2] 18 5b [2] 14 51 [2] 03 5a [2] 18 14 [2] 25 }

  condition:
    any of them
}