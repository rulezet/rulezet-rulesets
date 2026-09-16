rule TTP_XOR_MULT_DOSStub_7246 {
  strings:
    $key_7246 = { 26 2e [2] 52 36 [2] 15 34 [2] 52 25 [2] 1c 29 [2] 10 23 [2] 07 28 [2] 1c 66 [2] 21 }

  condition:
    any of them
}