rule TTP_XOR_MULT_DOSStub_34b4 {
  strings:
    $key_34b4 = { 60 dc [2] 14 c4 [2] 53 c6 [2] 14 d7 [2] 5a db [2] 56 d1 [2] 41 da [2] 5a 94 [2] 67 }

  condition:
    any of them
}