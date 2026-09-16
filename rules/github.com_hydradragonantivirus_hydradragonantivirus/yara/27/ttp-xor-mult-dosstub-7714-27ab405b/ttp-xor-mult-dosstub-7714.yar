rule TTP_XOR_MULT_DOSStub_7714 {
  strings:
    $key_7714 = { 23 7c [2] 57 64 [2] 10 66 [2] 57 77 [2] 19 7b [2] 15 71 [2] 02 7a [2] 19 34 [2] 24 }

  condition:
    any of them
}