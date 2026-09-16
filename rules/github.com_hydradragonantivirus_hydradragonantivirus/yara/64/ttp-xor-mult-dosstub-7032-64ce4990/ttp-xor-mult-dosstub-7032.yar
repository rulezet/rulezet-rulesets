rule TTP_XOR_MULT_DOSStub_7032 {
  strings:
    $key_7032 = { 24 5a [2] 50 42 [2] 17 40 [2] 50 51 [2] 1e 5d [2] 12 57 [2] 05 5c [2] 1e 12 [2] 23 }

  condition:
    any of them
}