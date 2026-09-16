rule TTP_XOR_MULT_DOSStub_78f1 {
  strings:
    $key_78f1 = { 2c 99 [2] 58 81 [2] 1f 83 [2] 58 92 [2] 16 9e [2] 1a 94 [2] 0d 9f [2] 16 d1 [2] 2b }

  condition:
    any of them
}