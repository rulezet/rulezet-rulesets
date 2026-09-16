rule TTP_XOR_MULT_DOSStub_7414 {
  strings:
    $key_7414 = { 20 7c [2] 54 64 [2] 13 66 [2] 54 77 [2] 1a 7b [2] 16 71 [2] 01 7a [2] 1a 34 [2] 27 }

  condition:
    any of them
}