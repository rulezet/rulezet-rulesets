rule TTP_XOR_MULT_DOSStub_4bf1 {
  strings:
    $key_4bf1 = { 1f 99 [2] 6b 81 [2] 2c 83 [2] 6b 92 [2] 25 9e [2] 29 94 [2] 3e 9f [2] 25 d1 [2] 18 }

  condition:
    any of them
}