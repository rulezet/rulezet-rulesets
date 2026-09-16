rule TTP_XOR_MULT_DOSStub_5804 {
  strings:
    $key_5804 = { 0c 6c [2] 78 74 [2] 3f 76 [2] 78 67 [2] 36 6b [2] 3a 61 [2] 2d 6a [2] 36 24 [2] 0b }

  condition:
    any of them
}