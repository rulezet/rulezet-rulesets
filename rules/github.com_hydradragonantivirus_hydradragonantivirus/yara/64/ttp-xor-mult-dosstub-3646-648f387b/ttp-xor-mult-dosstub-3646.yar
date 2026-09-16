rule TTP_XOR_MULT_DOSStub_3646 {
  strings:
    $key_3646 = { 62 2e [2] 16 36 [2] 51 34 [2] 16 25 [2] 58 29 [2] 54 23 [2] 43 28 [2] 58 66 [2] 65 }

  condition:
    any of them
}