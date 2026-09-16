rule TTP_XOR_MULT_DOSStub_59f6 {
  strings:
    $key_59f6 = { 0d 9e [2] 79 86 [2] 3e 84 [2] 79 95 [2] 37 99 [2] 3b 93 [2] 2c 98 [2] 37 d6 [2] 0a }

  condition:
    any of them
}