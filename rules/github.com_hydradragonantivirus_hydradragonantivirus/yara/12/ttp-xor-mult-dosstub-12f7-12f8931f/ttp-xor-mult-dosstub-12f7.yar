rule TTP_XOR_MULT_DOSStub_12f7 {
  strings:
    $key_12f7 = { 46 9f [2] 32 87 [2] 75 85 [2] 32 94 [2] 7c 98 [2] 70 92 [2] 67 99 [2] 7c d7 [2] 41 }

  condition:
    any of them
}