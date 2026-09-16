rule TTP_XOR_MULT_DOSStub_5802 {
  strings:
    $key_5802 = { 0c 6a [2] 78 72 [2] 3f 70 [2] 78 61 [2] 36 6d [2] 3a 67 [2] 2d 6c [2] 36 22 [2] 0b }

  condition:
    any of them
}