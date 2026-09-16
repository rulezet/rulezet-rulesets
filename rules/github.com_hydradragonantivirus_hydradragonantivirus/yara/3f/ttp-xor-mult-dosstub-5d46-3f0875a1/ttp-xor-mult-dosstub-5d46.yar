rule TTP_XOR_MULT_DOSStub_5d46 {
  strings:
    $key_5d46 = { 09 2e [2] 7d 36 [2] 3a 34 [2] 7d 25 [2] 33 29 [2] 3f 23 [2] 28 28 [2] 33 66 [2] 0e }

  condition:
    any of them
}