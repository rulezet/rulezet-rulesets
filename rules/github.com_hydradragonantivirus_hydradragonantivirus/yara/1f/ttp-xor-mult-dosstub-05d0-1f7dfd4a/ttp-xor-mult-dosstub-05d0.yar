rule TTP_XOR_MULT_DOSStub_05d0 {
  strings:
    $key_05d0 = { 51 b8 [2] 25 a0 [2] 62 a2 [2] 25 b3 [2] 6b bf [2] 67 b5 [2] 70 be [2] 6b f0 [2] 56 }

  condition:
    any of them
}