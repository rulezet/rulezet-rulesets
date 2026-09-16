rule TTP_XOR_MULT_DOSStub_4ef0 {
  strings:
    $key_4ef0 = { 1a 98 [2] 6e 80 [2] 29 82 [2] 6e 93 [2] 20 9f [2] 2c 95 [2] 3b 9e [2] 20 d0 [2] 1d }

  condition:
    any of them
}