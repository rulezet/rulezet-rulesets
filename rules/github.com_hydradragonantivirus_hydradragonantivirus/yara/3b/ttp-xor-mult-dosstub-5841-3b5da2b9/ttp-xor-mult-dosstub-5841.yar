rule TTP_XOR_MULT_DOSStub_5841 {
  strings:
    $key_5841 = { 0c 29 [2] 78 31 [2] 3f 33 [2] 78 22 [2] 36 2e [2] 3a 24 [2] 2d 2f [2] 36 61 [2] 0b }

  condition:
    any of them
}