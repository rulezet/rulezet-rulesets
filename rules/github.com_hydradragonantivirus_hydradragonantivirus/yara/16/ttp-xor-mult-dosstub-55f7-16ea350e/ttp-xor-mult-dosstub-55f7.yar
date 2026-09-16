rule TTP_XOR_MULT_DOSStub_55f7 {
  strings:
    $key_55f7 = { 01 9f [2] 75 87 [2] 32 85 [2] 75 94 [2] 3b 98 [2] 37 92 [2] 20 99 [2] 3b d7 [2] 06 }

  condition:
    any of them
}