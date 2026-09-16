rule TTP_XOR_MULT_DOSStub_78f6 {
  strings:
    $key_78f6 = { 2c 9e [2] 58 86 [2] 1f 84 [2] 58 95 [2] 16 99 [2] 1a 93 [2] 0d 98 [2] 16 d6 [2] 2b }

  condition:
    any of them
}