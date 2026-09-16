rule TTP_XOR_MULT_DOSStub_13b4 {
  strings:
    $key_13b4 = { 47 dc [2] 33 c4 [2] 74 c6 [2] 33 d7 [2] 7d db [2] 71 d1 [2] 66 da [2] 7d 94 [2] 40 }

  condition:
    any of them
}