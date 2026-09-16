rule TTP_XOR_MULT_DOSStub_72b4 {
  strings:
    $key_72b4 = { 26 dc [2] 52 c4 [2] 15 c6 [2] 52 d7 [2] 1c db [2] 10 d1 [2] 07 da [2] 1c 94 [2] 21 }

  condition:
    any of them
}