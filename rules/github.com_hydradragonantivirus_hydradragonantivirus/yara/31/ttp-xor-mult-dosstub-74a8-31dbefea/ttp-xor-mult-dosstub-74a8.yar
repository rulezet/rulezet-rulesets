rule TTP_XOR_MULT_DOSStub_74a8 {
  strings:
    $key_74a8 = { 20 c0 [2] 54 d8 [2] 13 da [2] 54 cb [2] 1a c7 [2] 16 cd [2] 01 c6 [2] 1a 88 [2] 27 }

  condition:
    any of them
}