rule TTP_XOR_MULT_DOSStub_71f7 {
  strings:
    $key_71f7 = { 25 9f [2] 51 87 [2] 16 85 [2] 51 94 [2] 1f 98 [2] 13 92 [2] 04 99 [2] 1f d7 [2] 22 }

  condition:
    any of them
}