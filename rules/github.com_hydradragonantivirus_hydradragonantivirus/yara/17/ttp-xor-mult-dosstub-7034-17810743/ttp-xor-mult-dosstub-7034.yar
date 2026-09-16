rule TTP_XOR_MULT_DOSStub_7034 {
  strings:
    $key_7034 = { 24 5c [2] 50 44 [2] 17 46 [2] 50 57 [2] 1e 5b [2] 12 51 [2] 05 5a [2] 1e 14 [2] 23 }

  condition:
    any of them
}