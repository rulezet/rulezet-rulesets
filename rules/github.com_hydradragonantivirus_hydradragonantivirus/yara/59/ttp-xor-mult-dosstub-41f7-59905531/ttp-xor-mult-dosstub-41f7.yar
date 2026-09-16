rule TTP_XOR_MULT_DOSStub_41f7 {
  strings:
    $key_41f7 = { 15 9f [2] 61 87 [2] 26 85 [2] 61 94 [2] 2f 98 [2] 23 92 [2] 34 99 [2] 2f d7 [2] 12 }

  condition:
    any of them
}