rule TTP_XOR_MULT_DOSStub_7075 {
  strings:
    $key_7075 = { 24 1d [2] 50 05 [2] 17 07 [2] 50 16 [2] 1e 1a [2] 12 10 [2] 05 1b [2] 1e 55 [2] 23 }

  condition:
    any of them
}