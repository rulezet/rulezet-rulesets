rule TTP_XOR_MULT_DOSStub_7746 {
  strings:
    $key_7746 = { 23 2e [2] 57 36 [2] 10 34 [2] 57 25 [2] 19 29 [2] 15 23 [2] 02 28 [2] 19 66 [2] 24 }

  condition:
    any of them
}