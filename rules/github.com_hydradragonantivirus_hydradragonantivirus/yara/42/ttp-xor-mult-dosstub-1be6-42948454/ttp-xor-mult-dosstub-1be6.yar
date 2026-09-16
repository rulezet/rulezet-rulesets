rule TTP_XOR_MULT_DOSStub_1be6 {
  strings:
    $key_1be6 = { 4f 8e [2] 3b 96 [2] 7c 94 [2] 3b 85 [2] 75 89 [2] 79 83 [2] 6e 88 [2] 75 c6 [2] 48 }

  condition:
    any of them
}