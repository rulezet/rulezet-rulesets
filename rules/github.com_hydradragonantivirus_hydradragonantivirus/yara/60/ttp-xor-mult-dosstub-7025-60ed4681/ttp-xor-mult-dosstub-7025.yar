rule TTP_XOR_MULT_DOSStub_7025 {
  strings:
    $key_7025 = { 24 4d [2] 50 55 [2] 17 57 [2] 50 46 [2] 1e 4a [2] 12 40 [2] 05 4b [2] 1e 05 [2] 23 }

  condition:
    any of them
}