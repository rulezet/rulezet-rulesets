rule TTP_XOR_MULT_DOSStub_0b46 {
  strings:
    $key_0b46 = { 5f 2e [2] 2b 36 [2] 6c 34 [2] 2b 25 [2] 65 29 [2] 69 23 [2] 7e 28 [2] 65 66 [2] 58 }

  condition:
    any of them
}