rule TTP_XOR_MULT_DOSStub_0462 {
  strings:
    $key_0462 = { 50 0a [2] 24 12 [2] 63 10 [2] 24 01 [2] 6a 0d [2] 66 07 [2] 71 0c [2] 6a 42 [2] 57 }

  condition:
    any of them
}