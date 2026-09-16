rule TTP_XOR_MULT_DOSStub_7018 {
  strings:
    $key_7018 = { 24 70 [2] 50 68 [2] 17 6a [2] 50 7b [2] 1e 77 [2] 12 7d [2] 05 76 [2] 1e 38 [2] 23 }

  condition:
    any of them
}