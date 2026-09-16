rule TTP_XOR_MULT_DOSStub_00d0 {
  strings:
    $key_00d0 = { 54 b8 [2] 20 a0 [2] 67 a2 [2] 20 b3 [2] 6e bf [2] 62 b5 [2] 75 be [2] 6e f0 [2] 53 }

  condition:
    any of them
}