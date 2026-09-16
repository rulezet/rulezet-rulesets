rule TTP_XOR_MULT_DOSStub_5df1 {
  strings:
    $key_5df1 = { 09 99 [2] 7d 81 [2] 3a 83 [2] 7d 92 [2] 33 9e [2] 3f 94 [2] 28 9f [2] 33 d1 [2] 0e }

  condition:
    any of them
}