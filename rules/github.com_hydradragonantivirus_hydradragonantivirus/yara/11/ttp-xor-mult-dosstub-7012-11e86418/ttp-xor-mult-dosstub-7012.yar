rule TTP_XOR_MULT_DOSStub_7012 {
  strings:
    $key_7012 = { 24 7a [2] 50 62 [2] 17 60 [2] 50 71 [2] 1e 7d [2] 12 77 [2] 05 7c [2] 1e 32 [2] 23 }

  condition:
    any of them
}