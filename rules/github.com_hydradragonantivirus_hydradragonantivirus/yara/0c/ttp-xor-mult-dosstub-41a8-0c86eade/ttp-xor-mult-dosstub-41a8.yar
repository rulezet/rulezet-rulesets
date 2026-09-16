rule TTP_XOR_MULT_DOSStub_41a8 {
  strings:
    $key_41a8 = { 15 c0 [2] 61 d8 [2] 26 da [2] 61 cb [2] 2f c7 [2] 23 cd [2] 34 c6 [2] 2f 88 [2] 12 }

  condition:
    any of them
}