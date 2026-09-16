rule TTP_XOR_MULT_DOSStub_58e8 {
  strings:
    $key_58e8 = { 0c 80 [2] 78 98 [2] 3f 9a [2] 78 8b [2] 36 87 [2] 3a 8d [2] 2d 86 [2] 36 c8 [2] 0b }

  condition:
    any of them
}