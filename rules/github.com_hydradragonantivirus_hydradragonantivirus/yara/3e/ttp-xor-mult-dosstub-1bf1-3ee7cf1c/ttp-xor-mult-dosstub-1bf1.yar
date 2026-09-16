rule TTP_XOR_MULT_DOSStub_1bf1 {
  strings:
    $key_1bf1 = { 4f 99 [2] 3b 81 [2] 7c 83 [2] 3b 92 [2] 75 9e [2] 79 94 [2] 6e 9f [2] 75 d1 [2] 48 }

  condition:
    any of them
}