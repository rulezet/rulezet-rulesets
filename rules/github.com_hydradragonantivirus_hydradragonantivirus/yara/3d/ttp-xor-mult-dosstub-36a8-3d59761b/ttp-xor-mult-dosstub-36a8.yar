rule TTP_XOR_MULT_DOSStub_36a8 {
  strings:
    $key_36a8 = { 62 c0 [2] 16 d8 [2] 51 da [2] 16 cb [2] 58 c7 [2] 54 cd [2] 43 c6 [2] 58 88 [2] 65 }

  condition:
    any of them
}