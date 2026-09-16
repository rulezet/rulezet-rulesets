rule TTP_XOR_MULT_DOSStub_16f7 {
  strings:
    $key_16f7 = { 42 9f [2] 36 87 [2] 71 85 [2] 36 94 [2] 78 98 [2] 74 92 [2] 63 99 [2] 78 d7 [2] 45 }

  condition:
    any of them
}