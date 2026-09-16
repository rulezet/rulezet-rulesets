rule TTP_XOR_MULT_DOSStub_34b9 {
  strings:
    $key_34b9 = { 60 d1 [2] 14 c9 [2] 53 cb [2] 14 da [2] 5a d6 [2] 56 dc [2] 41 d7 [2] 5a 99 [2] 67 }

  condition:
    any of them
}