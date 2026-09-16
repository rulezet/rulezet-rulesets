rule TTP_XOR_MULT_DOSStub_4131 {
  strings:
    $key_4131 = { 15 59 [2] 61 41 [2] 26 43 [2] 61 52 [2] 2f 5e [2] 23 54 [2] 34 5f [2] 2f 11 [2] 12 }

  condition:
    any of them
}