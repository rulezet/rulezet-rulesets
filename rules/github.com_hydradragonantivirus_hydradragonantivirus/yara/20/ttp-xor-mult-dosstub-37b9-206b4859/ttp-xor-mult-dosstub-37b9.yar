rule TTP_XOR_MULT_DOSStub_37b9 {
  strings:
    $key_37b9 = { 63 d1 [2] 17 c9 [2] 50 cb [2] 17 da [2] 59 d6 [2] 55 dc [2] 42 d7 [2] 59 99 [2] 64 }

  condition:
    any of them
}