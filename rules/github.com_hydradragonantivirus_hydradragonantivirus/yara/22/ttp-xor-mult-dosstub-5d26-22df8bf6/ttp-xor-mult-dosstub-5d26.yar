rule TTP_XOR_MULT_DOSStub_5d26 {
  strings:
    $key_5d26 = { 09 4e [2] 7d 56 [2] 3a 54 [2] 7d 45 [2] 33 49 [2] 3f 43 [2] 28 48 [2] 33 06 [2] 0e }

  condition:
    any of them
}