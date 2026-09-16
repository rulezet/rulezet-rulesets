rule TTP_XOR_MULT_DOSStub_64a8 {
  strings:
    $key_64a8 = { 30 c0 [2] 44 d8 [2] 03 da [2] 44 cb [2] 0a c7 [2] 06 cd [2] 11 c6 [2] 0a 88 [2] 37 }

  condition:
    any of them
}