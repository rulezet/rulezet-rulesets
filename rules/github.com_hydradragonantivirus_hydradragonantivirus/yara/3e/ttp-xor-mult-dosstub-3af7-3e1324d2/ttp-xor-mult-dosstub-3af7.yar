rule TTP_XOR_MULT_DOSStub_3af7 {
  strings:
    $key_3af7 = { 6e 9f [2] 1a 87 [2] 5d 85 [2] 1a 94 [2] 54 98 [2] 58 92 [2] 4f 99 [2] 54 d7 [2] 69 }

  condition:
    any of them
}