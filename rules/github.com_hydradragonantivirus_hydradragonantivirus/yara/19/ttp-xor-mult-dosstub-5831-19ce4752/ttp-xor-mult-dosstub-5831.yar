rule TTP_XOR_MULT_DOSStub_5831 {
  strings:
    $key_5831 = { 0c 59 [2] 78 41 [2] 3f 43 [2] 78 52 [2] 36 5e [2] 3a 54 [2] 2d 5f [2] 36 11 [2] 0b }

  condition:
    any of them
}