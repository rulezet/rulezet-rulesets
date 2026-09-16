rule TTP_XOR_MULT_DOSStub_3346 {
  strings:
    $key_3346 = { 67 2e [2] 13 36 [2] 54 34 [2] 13 25 [2] 5d 29 [2] 51 23 [2] 46 28 [2] 5d 66 [2] 60 }

  condition:
    any of them
}