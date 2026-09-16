rule TTP_XOR_MULT_DOSStub_06b9 {
  strings:
    $key_06b9 = { 52 d1 [2] 26 c9 [2] 61 cb [2] 26 da [2] 68 d6 [2] 64 dc [2] 73 d7 [2] 68 99 [2] 55 }

  condition:
    any of them
}