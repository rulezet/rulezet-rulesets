rule TTP_XOR_MULT_DOSStub_42a8 {
  strings:
    $key_42a8 = { 16 c0 [2] 62 d8 [2] 25 da [2] 62 cb [2] 2c c7 [2] 20 cd [2] 37 c6 [2] 2c 88 [2] 11 }

  condition:
    any of them
}