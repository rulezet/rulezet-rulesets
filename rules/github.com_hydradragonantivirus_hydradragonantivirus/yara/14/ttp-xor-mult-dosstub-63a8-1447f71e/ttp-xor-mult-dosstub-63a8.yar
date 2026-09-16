rule TTP_XOR_MULT_DOSStub_63a8 {
  strings:
    $key_63a8 = { 37 c0 [2] 43 d8 [2] 04 da [2] 43 cb [2] 0d c7 [2] 01 cd [2] 16 c6 [2] 0d 88 [2] 30 }

  condition:
    any of them
}