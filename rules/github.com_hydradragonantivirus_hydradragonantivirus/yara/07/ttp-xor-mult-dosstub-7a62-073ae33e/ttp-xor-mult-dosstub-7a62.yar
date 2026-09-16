rule TTP_XOR_MULT_DOSStub_7a62 {
  strings:
    $key_7a62 = { 2e 0a [2] 5a 12 [2] 1d 10 [2] 5a 01 [2] 14 0d [2] 18 07 [2] 0f 0c [2] 14 42 [2] 29 }

  condition:
    any of them
}