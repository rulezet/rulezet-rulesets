rule TTP_XOR_MULT_DOSStub_7045 {
  strings:
    $key_7045 = { 24 2d [2] 50 35 [2] 17 37 [2] 50 26 [2] 1e 2a [2] 12 20 [2] 05 2b [2] 1e 65 [2] 23 }

  condition:
    any of them
}