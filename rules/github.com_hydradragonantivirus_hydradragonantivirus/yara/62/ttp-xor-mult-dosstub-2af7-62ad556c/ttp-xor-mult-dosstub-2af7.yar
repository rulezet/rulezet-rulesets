rule TTP_XOR_MULT_DOSStub_2af7 {
  strings:
    $key_2af7 = { 7e 9f [2] 0a 87 [2] 4d 85 [2] 0a 94 [2] 44 98 [2] 48 92 [2] 5f 99 [2] 44 d7 [2] 79 }

  condition:
    any of them
}