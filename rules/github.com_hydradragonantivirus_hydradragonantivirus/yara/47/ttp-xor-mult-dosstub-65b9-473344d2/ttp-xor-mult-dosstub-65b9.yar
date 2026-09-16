rule TTP_XOR_MULT_DOSStub_65b9 {
  strings:
    $key_65b9 = { 31 d1 [2] 45 c9 [2] 02 cb [2] 45 da [2] 0b d6 [2] 07 dc [2] 10 d7 [2] 0b 99 [2] 36 }

  condition:
    any of them
}