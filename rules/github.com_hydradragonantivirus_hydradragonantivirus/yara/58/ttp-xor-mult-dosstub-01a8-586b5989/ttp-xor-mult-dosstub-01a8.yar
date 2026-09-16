rule TTP_XOR_MULT_DOSStub_01a8 {
  strings:
    $key_01a8 = { 55 c0 [2] 21 d8 [2] 66 da [2] 21 cb [2] 6f c7 [2] 63 cd [2] 74 c6 [2] 6f 88 [2] 52 }

  condition:
    any of them
}