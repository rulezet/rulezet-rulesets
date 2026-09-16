rule TTP_XOR_MULT_DOSStub_37b4 {
  strings:
    $key_37b4 = { 63 dc [2] 17 c4 [2] 50 c6 [2] 17 d7 [2] 59 db [2] 55 d1 [2] 42 da [2] 59 94 [2] 64 }

  condition:
    any of them
}