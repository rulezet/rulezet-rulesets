rule TTP_XOR_MULT_DOSStub_58f5 {
  strings:
    $key_58f5 = { 0c 9d [2] 78 85 [2] 3f 87 [2] 78 96 [2] 36 9a [2] 3a 90 [2] 2d 9b [2] 36 d5 [2] 0b }

  condition:
    any of them
}