rule TTP_XOR_MULT_DOSStub_77f7 {
  strings:
    $key_77f7 = { 23 9f [2] 57 87 [2] 10 85 [2] 57 94 [2] 19 98 [2] 15 92 [2] 02 99 [2] 19 d7 [2] 24 }

  condition:
    any of them
}