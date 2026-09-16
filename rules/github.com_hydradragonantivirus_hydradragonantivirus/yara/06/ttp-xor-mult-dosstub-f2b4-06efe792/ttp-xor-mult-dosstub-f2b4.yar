rule TTP_XOR_MULT_DOSStub_f2b4 {
  strings:
    $key_f2b4 = { a6 dc [2] d2 c4 [2] 95 c6 [2] d2 d7 [2] 9c db [2] 90 d1 [2] 87 da [2] 9c 94 [2] a1 }

  condition:
    any of them
}