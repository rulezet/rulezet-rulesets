rule TTP_XOR_MULT_DOSStub_3834 {
  strings:
    $key_3834 = { 6c 5c [2] 18 44 [2] 5f 46 [2] 18 57 [2] 56 5b [2] 5a 51 [2] 4d 5a [2] 56 14 [2] 6b }

  condition:
    any of them
}