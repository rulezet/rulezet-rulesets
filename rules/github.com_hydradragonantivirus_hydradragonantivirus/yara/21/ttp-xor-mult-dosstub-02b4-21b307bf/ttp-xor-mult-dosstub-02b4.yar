rule TTP_XOR_MULT_DOSStub_02b4 {
  strings:
    $key_02b4 = { 56 dc [2] 22 c4 [2] 65 c6 [2] 22 d7 [2] 6c db [2] 60 d1 [2] 77 da [2] 6c 94 [2] 51 }

  condition:
    any of them
}