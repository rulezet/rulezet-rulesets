rule TTP_XOR_MULT_DOSStub_5857 {
  strings:
    $key_5857 = { 0c 3f [2] 78 27 [2] 3f 25 [2] 78 34 [2] 36 38 [2] 3a 32 [2] 2d 39 [2] 36 77 [2] 0b }

  condition:
    any of them
}