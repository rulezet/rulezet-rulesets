rule TTP_XOR_MULT_DOSStub_35a8 {
  strings:
    $key_35a8 = { 61 c0 [2] 15 d8 [2] 52 da [2] 15 cb [2] 5b c7 [2] 57 cd [2] 40 c6 [2] 5b 88 [2] 66 }

  condition:
    any of them
}