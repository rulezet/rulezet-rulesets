rule TTP_XOR_MULT_DOSStub_7005 {
  strings:
    $key_7005 = { 24 6d [2] 50 75 [2] 17 77 [2] 50 66 [2] 1e 6a [2] 12 60 [2] 05 6b [2] 1e 25 [2] 23 }

  condition:
    any of them
}