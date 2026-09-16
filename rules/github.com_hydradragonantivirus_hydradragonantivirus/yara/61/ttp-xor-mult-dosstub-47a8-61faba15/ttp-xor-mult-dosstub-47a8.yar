rule TTP_XOR_MULT_DOSStub_47a8 {
  strings:
    $key_47a8 = { 13 c0 [2] 67 d8 [2] 20 da [2] 67 cb [2] 29 c7 [2] 25 cd [2] 32 c6 [2] 29 88 [2] 14 }

  condition:
    any of them
}