rule TTP_XOR_MULT_DOSStub_58b2 {
  strings:
    $key_58b2 = { 0c da [2] 78 c2 [2] 3f c0 [2] 78 d1 [2] 36 dd [2] 3a d7 [2] 2d dc [2] 36 92 [2] 0b }

  condition:
    any of them
}