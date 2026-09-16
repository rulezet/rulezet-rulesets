rule TTP_XOR_MULT_DOSStub_5df6 {
  strings:
    $key_5df6 = { 09 9e [2] 7d 86 [2] 3a 84 [2] 7d 95 [2] 33 99 [2] 3f 93 [2] 28 98 [2] 33 d6 [2] 0e }

  condition:
    any of them
}