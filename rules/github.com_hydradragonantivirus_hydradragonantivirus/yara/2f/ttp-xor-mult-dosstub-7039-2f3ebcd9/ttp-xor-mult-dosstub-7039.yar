rule TTP_XOR_MULT_DOSStub_7039 {
  strings:
    $key_7039 = { 24 51 [2] 50 49 [2] 17 4b [2] 50 5a [2] 1e 56 [2] 12 5c [2] 05 57 [2] 1e 19 [2] 23 }

  condition:
    any of them
}