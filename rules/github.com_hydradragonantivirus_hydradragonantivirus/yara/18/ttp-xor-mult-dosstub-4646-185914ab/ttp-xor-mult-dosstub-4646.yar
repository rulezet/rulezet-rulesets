rule TTP_XOR_MULT_DOSStub_4646 {
  strings:
    $key_4646 = { 12 2e [2] 66 36 [2] 21 34 [2] 66 25 [2] 28 29 [2] 24 23 [2] 33 28 [2] 28 66 [2] 15 }

  condition:
    any of them
}