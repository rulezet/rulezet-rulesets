rule TTP_XOR_MULT_DOSStub_4ef1 {
  strings:
    $key_4ef1 = { 1a 99 [2] 6e 81 [2] 29 83 [2] 6e 92 [2] 20 9e [2] 2c 94 [2] 3b 9f [2] 20 d1 [2] 1d }

  condition:
    any of them
}