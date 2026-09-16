rule TTP_XOR_MULT_DOSStub_4630 {
  strings:
    $key_4630 = { 12 58 [2] 66 40 [2] 21 42 [2] 66 53 [2] 28 5f [2] 24 55 [2] 33 5e [2] 28 10 [2] 15 }

  condition:
    any of them
}