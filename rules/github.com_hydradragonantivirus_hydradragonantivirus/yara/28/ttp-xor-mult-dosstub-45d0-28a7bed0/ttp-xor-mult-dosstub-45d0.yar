rule TTP_XOR_MULT_DOSStub_45d0 {
  strings:
    $key_45d0 = { 11 b8 [2] 65 a0 [2] 22 a2 [2] 65 b3 [2] 2b bf [2] 27 b5 [2] 30 be [2] 2b f0 [2] 16 }

  condition:
    any of them
}