rule TTP_XOR_MULT_DOSStub_62f7 {
  strings:
    $key_62f7 = { 36 9f [2] 42 87 [2] 05 85 [2] 42 94 [2] 0c 98 [2] 00 92 [2] 17 99 [2] 0c d7 [2] 31 }

  condition:
    any of them
}