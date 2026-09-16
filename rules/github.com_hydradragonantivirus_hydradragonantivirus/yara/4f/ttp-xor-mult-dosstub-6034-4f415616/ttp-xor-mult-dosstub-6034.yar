rule TTP_XOR_MULT_DOSStub_6034 {
  strings:
    $key_6034 = { 34 5c [2] 40 44 [2] 07 46 [2] 40 57 [2] 0e 5b [2] 02 51 [2] 15 5a [2] 0e 14 [2] 33 }

  condition:
    any of them
}