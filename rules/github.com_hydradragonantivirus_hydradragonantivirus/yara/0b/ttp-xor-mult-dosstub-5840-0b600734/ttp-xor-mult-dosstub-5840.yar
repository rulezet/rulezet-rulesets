rule TTP_XOR_MULT_DOSStub_5840 {
  strings:
    $key_5840 = { 0c 28 [2] 78 30 [2] 3f 32 [2] 78 23 [2] 36 2f [2] 3a 25 [2] 2d 2e [2] 36 60 [2] 0b }

  condition:
    any of them
}