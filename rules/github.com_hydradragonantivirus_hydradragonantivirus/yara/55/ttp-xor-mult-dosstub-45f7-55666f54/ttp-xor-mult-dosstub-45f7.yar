rule TTP_XOR_MULT_DOSStub_45f7 {
  strings:
    $key_45f7 = { 11 9f [2] 65 87 [2] 22 85 [2] 65 94 [2] 2b 98 [2] 27 92 [2] 30 99 [2] 2b d7 [2] 16 }

  condition:
    any of them
}