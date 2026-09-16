rule TTP_XOR_MULT_DOSStub_64f7 {
  strings:
    $key_64f7 = { 30 9f [2] 44 87 [2] 03 85 [2] 44 94 [2] 0a 98 [2] 06 92 [2] 11 99 [2] 0a d7 [2] 37 }

  condition:
    any of them
}