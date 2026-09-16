rule TTP_XOR_MULT_DOSStub_25d0 {
  strings:
    $key_25d0 = { 71 b8 [2] 05 a0 [2] 42 a2 [2] 05 b3 [2] 4b bf [2] 47 b5 [2] 50 be [2] 4b f0 [2] 76 }

  condition:
    any of them
}