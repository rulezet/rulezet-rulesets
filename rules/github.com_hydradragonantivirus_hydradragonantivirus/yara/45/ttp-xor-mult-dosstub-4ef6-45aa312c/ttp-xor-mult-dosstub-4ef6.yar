rule TTP_XOR_MULT_DOSStub_4ef6 {
  strings:
    $key_4ef6 = { 1a 9e [2] 6e 86 [2] 29 84 [2] 6e 95 [2] 20 99 [2] 2c 93 [2] 3b 98 [2] 20 d6 [2] 1d }

  condition:
    any of them
}