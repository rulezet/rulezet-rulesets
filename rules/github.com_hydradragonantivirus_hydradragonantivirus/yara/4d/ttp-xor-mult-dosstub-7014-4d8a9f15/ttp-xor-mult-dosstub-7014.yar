rule TTP_XOR_MULT_DOSStub_7014 {
  strings:
    $key_7014 = { 24 7c [2] 50 64 [2] 17 66 [2] 50 77 [2] 1e 7b [2] 12 71 [2] 05 7a [2] 1e 34 [2] 23 }

  condition:
    any of them
}