rule TTP_XOR_MULT_DOSStub_76b4 {
  strings:
    $key_76b4 = { 22 dc [2] 56 c4 [2] 11 c6 [2] 56 d7 [2] 18 db [2] 14 d1 [2] 03 da [2] 18 94 [2] 25 }

  condition:
    any of them
}