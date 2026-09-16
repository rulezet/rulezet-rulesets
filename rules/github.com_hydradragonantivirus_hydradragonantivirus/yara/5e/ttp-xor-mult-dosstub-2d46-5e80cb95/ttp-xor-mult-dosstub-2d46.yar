rule TTP_XOR_MULT_DOSStub_2d46 {
  strings:
    $key_2d46 = { 79 2e [2] 0d 36 [2] 4a 34 [2] 0d 25 [2] 43 29 [2] 4f 23 [2] 58 28 [2] 43 66 [2] 7e }

  condition:
    any of them
}