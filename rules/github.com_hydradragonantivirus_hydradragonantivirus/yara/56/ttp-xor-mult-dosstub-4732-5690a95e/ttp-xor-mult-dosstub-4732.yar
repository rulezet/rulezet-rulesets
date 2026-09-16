rule TTP_XOR_MULT_DOSStub_4732 {
  strings:
    $key_4732 = { 13 5a [2] 67 42 [2] 20 40 [2] 67 51 [2] 29 5d [2] 25 57 [2] 32 5c [2] 29 12 [2] 14 }

  condition:
    any of them
}