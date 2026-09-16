rule TTP_XOR_MULT_DOSStub_7a46 {
  strings:
    $key_7a46 = { 2e 2e [2] 5a 36 [2] 1d 34 [2] 5a 25 [2] 14 29 [2] 18 23 [2] 0f 28 [2] 14 66 [2] 29 }

  condition:
    any of them
}