rule TTP_XOR_MULT_DOSStub_58e2 {
  strings:
    $key_58e2 = { 0c 8a [2] 78 92 [2] 3f 90 [2] 78 81 [2] 36 8d [2] 3a 87 [2] 2d 8c [2] 36 c2 [2] 0b }

  condition:
    any of them
}