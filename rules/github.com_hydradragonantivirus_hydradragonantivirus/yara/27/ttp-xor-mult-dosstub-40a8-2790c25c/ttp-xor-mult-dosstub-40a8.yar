rule TTP_XOR_MULT_DOSStub_40a8 {
  strings:
    $key_40a8 = { 14 c0 [2] 60 d8 [2] 27 da [2] 60 cb [2] 2e c7 [2] 22 cd [2] 35 c6 [2] 2e 88 [2] 13 }

  condition:
    any of them
}