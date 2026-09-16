rule TTP_XOR_MULT_DOSStub_58e4 {
  strings:
    $key_58e4 = { 0c 8c [2] 78 94 [2] 3f 96 [2] 78 87 [2] 36 8b [2] 3a 81 [2] 2d 8a [2] 36 c4 [2] 0b }

  condition:
    any of them
}