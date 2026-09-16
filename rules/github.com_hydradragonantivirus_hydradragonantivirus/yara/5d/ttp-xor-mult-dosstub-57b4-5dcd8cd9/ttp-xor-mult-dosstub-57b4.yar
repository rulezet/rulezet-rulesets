rule TTP_XOR_MULT_DOSStub_57b4 {
  strings:
    $key_57b4 = { 03 dc [2] 77 c4 [2] 30 c6 [2] 77 d7 [2] 39 db [2] 35 d1 [2] 22 da [2] 39 94 [2] 04 }

  condition:
    any of them
}