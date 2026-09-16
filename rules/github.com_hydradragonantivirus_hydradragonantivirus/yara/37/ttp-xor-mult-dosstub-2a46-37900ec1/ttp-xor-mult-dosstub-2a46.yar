rule TTP_XOR_MULT_DOSStub_2a46 {
  strings:
    $key_2a46 = { 7e 2e [2] 0a 36 [2] 4d 34 [2] 0a 25 [2] 44 29 [2] 48 23 [2] 5f 28 [2] 44 66 [2] 79 }

  condition:
    any of them
}