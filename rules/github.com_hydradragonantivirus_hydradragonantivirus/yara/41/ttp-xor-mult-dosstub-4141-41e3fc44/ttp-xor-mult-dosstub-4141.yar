rule TTP_XOR_MULT_DOSStub_4141 {
  strings:
    $key_4141 = { 15 29 [2] 61 31 [2] 26 33 [2] 61 22 [2] 2f 2e [2] 23 24 [2] 34 2f [2] 2f 61 [2] 12 }

  condition:
    any of them
}