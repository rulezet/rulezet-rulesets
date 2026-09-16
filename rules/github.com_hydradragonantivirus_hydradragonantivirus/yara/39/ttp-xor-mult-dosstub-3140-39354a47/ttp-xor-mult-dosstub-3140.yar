rule TTP_XOR_MULT_DOSStub_3140 {
  strings:
    $key_3140 = { 65 28 [2] 11 30 [2] 56 32 [2] 11 23 [2] 5f 2f [2] 53 25 [2] 44 2e [2] 5f 60 [2] 62 }

  condition:
    any of them
}