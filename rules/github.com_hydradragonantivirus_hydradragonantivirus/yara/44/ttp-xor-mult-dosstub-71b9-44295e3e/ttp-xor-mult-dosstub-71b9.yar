rule TTP_XOR_MULT_DOSStub_71b9 {
  strings:
    $key_71b9 = { 25 d1 [2] 51 c9 [2] 16 cb [2] 51 da [2] 1f d6 [2] 13 dc [2] 04 d7 [2] 1f 99 [2] 22 }

  condition:
    any of them
}