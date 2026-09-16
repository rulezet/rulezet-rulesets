rule TTP_XOR_MULT_DOSStub_4be6 {
  strings:
    $key_4be6 = { 1f 8e [2] 6b 96 [2] 2c 94 [2] 6b 85 [2] 25 89 [2] 29 83 [2] 3e 88 [2] 25 c6 [2] 18 }

  condition:
    any of them
}