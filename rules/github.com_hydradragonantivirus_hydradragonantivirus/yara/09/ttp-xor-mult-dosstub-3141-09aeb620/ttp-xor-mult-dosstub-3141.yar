rule TTP_XOR_MULT_DOSStub_3141 {
  strings:
    $key_3141 = { 65 29 [2] 11 31 [2] 56 33 [2] 11 22 [2] 5f 2e [2] 53 24 [2] 44 2f [2] 5f 61 [2] 62 }

  condition:
    any of them
}