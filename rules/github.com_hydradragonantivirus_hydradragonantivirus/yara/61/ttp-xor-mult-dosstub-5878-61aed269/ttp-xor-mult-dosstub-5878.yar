rule TTP_XOR_MULT_DOSStub_5878 {
  strings:
    $key_5878 = { 0c 10 [2] 78 08 [2] 3f 0a [2] 78 1b [2] 36 17 [2] 3a 1d [2] 2d 16 [2] 36 58 [2] 0b }

  condition:
    any of them
}