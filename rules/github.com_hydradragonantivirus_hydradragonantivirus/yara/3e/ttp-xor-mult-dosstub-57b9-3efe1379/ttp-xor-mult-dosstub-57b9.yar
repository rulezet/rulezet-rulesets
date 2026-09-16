rule TTP_XOR_MULT_DOSStub_57b9 {
  strings:
    $key_57b9 = { 03 d1 [2] 77 c9 [2] 30 cb [2] 77 da [2] 39 d6 [2] 35 dc [2] 22 d7 [2] 39 99 [2] 04 }

  condition:
    any of them
}