rule TTP_XOR_MULT_DOSStub_45a8 {
  strings:
    $key_45a8 = { 11 c0 [2] 65 d8 [2] 22 da [2] 65 cb [2] 2b c7 [2] 27 cd [2] 30 c6 [2] 2b 88 [2] 16 }

  condition:
    any of them
}