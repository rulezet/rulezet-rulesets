rule TTP_XOR_MULT_DOSStub_3146 {
  strings:
    $key_3146 = { 65 2e [2] 11 36 [2] 56 34 [2] 11 25 [2] 5f 29 [2] 53 23 [2] 44 28 [2] 5f 66 [2] 62 }

  condition:
    any of them
}