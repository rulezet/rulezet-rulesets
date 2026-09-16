rule TTP_XOR_MULT_DOSStub_7712 {
  strings:
    $key_7712 = { 23 7a [2] 57 62 [2] 10 60 [2] 57 71 [2] 19 7d [2] 15 77 [2] 02 7c [2] 19 32 [2] 24 }

  condition:
    any of them
}