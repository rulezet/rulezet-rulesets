rule TTP_XOR_MULT_DOSStub_71b4 {
  strings:
    $key_71b4 = { 25 dc [2] 51 c4 [2] 16 c6 [2] 51 d7 [2] 1f db [2] 13 d1 [2] 04 da [2] 1f 94 [2] 22 }

  condition:
    any of them
}