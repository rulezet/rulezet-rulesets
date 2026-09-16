rule TTP_XOR_MULT_DOSStub_5817 {
  strings:
    $key_5817 = { 0c 7f [2] 78 67 [2] 3f 65 [2] 78 74 [2] 36 78 [2] 3a 72 [2] 2d 79 [2] 36 37 [2] 0b }

  condition:
    any of them
}