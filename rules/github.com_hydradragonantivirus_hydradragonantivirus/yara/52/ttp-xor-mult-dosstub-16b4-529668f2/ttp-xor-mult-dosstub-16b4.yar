rule TTP_XOR_MULT_DOSStub_16b4 {
  strings:
    $key_16b4 = { 42 dc [2] 36 c4 [2] 71 c6 [2] 36 d7 [2] 78 db [2] 74 d1 [2] 63 da [2] 78 94 [2] 45 }

  condition:
    any of them
}