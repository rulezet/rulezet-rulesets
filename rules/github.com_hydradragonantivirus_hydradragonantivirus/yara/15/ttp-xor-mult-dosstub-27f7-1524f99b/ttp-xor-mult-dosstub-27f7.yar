rule TTP_XOR_MULT_DOSStub_27f7 {
  strings:
    $key_27f7 = { 73 9f [2] 07 87 [2] 40 85 [2] 07 94 [2] 49 98 [2] 45 92 [2] 52 99 [2] 49 d7 [2] 74 }

  condition:
    any of them
}