rule TTP_XOR_MULT_DOSStub_4bf7 {
  strings:
    $key_4bf7 = { 1f 9f [2] 6b 87 [2] 2c 85 [2] 6b 94 [2] 25 98 [2] 29 92 [2] 3e 99 [2] 25 d7 [2] 18 }

  condition:
    any of them
}