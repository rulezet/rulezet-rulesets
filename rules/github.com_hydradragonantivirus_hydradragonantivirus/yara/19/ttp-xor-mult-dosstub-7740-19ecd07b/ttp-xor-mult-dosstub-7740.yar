rule TTP_XOR_MULT_DOSStub_7740 {
  strings:
    $key_7740 = { 23 28 [2] 57 30 [2] 10 32 [2] 57 23 [2] 19 2f [2] 15 25 [2] 02 2e [2] 19 60 [2] 24 }

  condition:
    any of them
}