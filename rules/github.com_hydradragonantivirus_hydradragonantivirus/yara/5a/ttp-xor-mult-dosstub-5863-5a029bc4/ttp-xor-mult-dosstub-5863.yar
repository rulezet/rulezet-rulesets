rule TTP_XOR_MULT_DOSStub_5863 {
  strings:
    $key_5863 = { 0c 0b [2] 78 13 [2] 3f 11 [2] 78 00 [2] 36 0c [2] 3a 06 [2] 2d 0d [2] 36 43 [2] 0b }

  condition:
    any of them
}