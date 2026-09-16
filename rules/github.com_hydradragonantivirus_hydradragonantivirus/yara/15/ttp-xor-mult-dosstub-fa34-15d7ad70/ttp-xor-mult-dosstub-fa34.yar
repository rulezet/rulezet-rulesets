rule TTP_XOR_MULT_DOSStub_fa34 {
  strings:
    $key_fa34 = { ae 5c [2] da 44 [2] 9d 46 [2] da 57 [2] 94 5b [2] 98 51 [2] 8f 5a [2] 94 14 [2] a9 }

  condition:
    any of them
}