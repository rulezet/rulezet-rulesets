rule TTP_XOR_MULT_DOSStub_01b4 {
  strings:
    $key_01b4 = { 55 dc [2] 21 c4 [2] 66 c6 [2] 21 d7 [2] 6f db [2] 63 d1 [2] 74 da [2] 6f 94 [2] 52 }

  condition:
    any of them
}