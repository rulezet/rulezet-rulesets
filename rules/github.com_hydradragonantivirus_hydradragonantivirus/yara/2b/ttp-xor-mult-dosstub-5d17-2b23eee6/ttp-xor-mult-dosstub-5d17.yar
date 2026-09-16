rule TTP_XOR_MULT_DOSStub_5d17 {
  strings:
    $key_5d17 = { 09 7f [2] 7d 67 [2] 3a 65 [2] 7d 74 [2] 33 78 [2] 3f 72 [2] 28 79 [2] 33 37 [2] 0e }

  condition:
    any of them
}