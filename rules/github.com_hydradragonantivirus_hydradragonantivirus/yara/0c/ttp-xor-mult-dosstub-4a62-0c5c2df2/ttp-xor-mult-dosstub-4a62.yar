rule TTP_XOR_MULT_DOSStub_4a62 {
  strings:
    $key_4a62 = { 1e 0a [2] 6a 12 [2] 2d 10 [2] 6a 01 [2] 24 0d [2] 28 07 [2] 3f 0c [2] 24 42 [2] 19 }

  condition:
    any of them
}