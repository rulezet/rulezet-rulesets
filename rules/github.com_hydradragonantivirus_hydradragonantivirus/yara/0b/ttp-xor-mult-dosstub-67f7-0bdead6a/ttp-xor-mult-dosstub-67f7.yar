rule TTP_XOR_MULT_DOSStub_67f7 {
  strings:
    $key_67f7 = { 33 9f [2] 47 87 [2] 00 85 [2] 47 94 [2] 09 98 [2] 05 92 [2] 12 99 [2] 09 d7 [2] 34 }

  condition:
    any of them
}