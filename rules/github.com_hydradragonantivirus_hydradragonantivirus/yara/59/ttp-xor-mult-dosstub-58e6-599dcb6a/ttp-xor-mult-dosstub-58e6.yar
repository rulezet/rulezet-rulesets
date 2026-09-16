rule TTP_XOR_MULT_DOSStub_58e6 {
  strings:
    $key_58e6 = { 0c 8e [2] 78 96 [2] 3f 94 [2] 78 85 [2] 36 89 [2] 3a 83 [2] 2d 88 [2] 36 c6 [2] 0b }

  condition:
    any of them
}