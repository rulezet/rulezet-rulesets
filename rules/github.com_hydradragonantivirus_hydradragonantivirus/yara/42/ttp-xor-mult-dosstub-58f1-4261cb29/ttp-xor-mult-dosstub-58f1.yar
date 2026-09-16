rule TTP_XOR_MULT_DOSStub_58f1 {
  strings:
    $key_58f1 = { 0c 99 [2] 78 81 [2] 3f 83 [2] 78 92 [2] 36 9e [2] 3a 94 [2] 2d 9f [2] 36 d1 [2] 0b }

  condition:
    any of them
}