rule TTP_XOR_MULT_DOSStub_7013 {
  strings:
    $key_7013 = { 24 7b [2] 50 63 [2] 17 61 [2] 50 70 [2] 1e 7c [2] 12 76 [2] 05 7d [2] 1e 33 [2] 23 }

  condition:
    any of them
}