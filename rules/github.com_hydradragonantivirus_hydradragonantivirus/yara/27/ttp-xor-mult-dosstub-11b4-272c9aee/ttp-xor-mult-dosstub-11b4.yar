rule TTP_XOR_MULT_DOSStub_11b4 {
  strings:
    $key_11b4 = { 45 dc [2] 31 c4 [2] 76 c6 [2] 31 d7 [2] 7f db [2] 73 d1 [2] 64 da [2] 7f 94 [2] 42 }

  condition:
    any of them
}