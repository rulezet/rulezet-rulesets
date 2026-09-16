rule TTP_XOR_MULT_DOSStub_4120 {
  strings:
    $key_4120 = { 15 48 [2] 61 50 [2] 26 52 [2] 61 43 [2] 2f 4f [2] 23 45 [2] 34 4e [2] 2f 00 [2] 12 }

  condition:
    any of them
}