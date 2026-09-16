rule TTP_XOR_MULT_DOSStub_5860 {
  strings:
    $key_5860 = { 0c 08 [2] 78 10 [2] 3f 12 [2] 78 03 [2] 36 0f [2] 3a 05 [2] 2d 0e [2] 36 40 [2] 0b }

  condition:
    any of them
}