rule TTP_XOR_MULT_DOSStub_15c8 {
  strings:
    $key_15c8 = { 41 a0 [2] 35 b8 [2] 72 ba [2] 35 ab [2] 7b a7 [2] 77 ad [2] 60 a6 [2] 7b e8 [2] 46 }

  condition:
    any of them
}