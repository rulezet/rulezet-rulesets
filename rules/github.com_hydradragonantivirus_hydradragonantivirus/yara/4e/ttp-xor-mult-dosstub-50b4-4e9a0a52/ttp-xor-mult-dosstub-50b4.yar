rule TTP_XOR_MULT_DOSStub_50b4 {
  strings:
    $key_50b4 = { 04 dc [2] 70 c4 [2] 37 c6 [2] 70 d7 [2] 3e db [2] 32 d1 [2] 25 da [2] 3e 94 [2] 03 }

  condition:
    any of them
}