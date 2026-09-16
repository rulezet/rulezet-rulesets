rule TTP_XOR_MULT_DOSStub_68b2 {
  strings:
    $key_68b2 = { 3c da [2] 48 c2 [2] 0f c0 [2] 48 d1 [2] 06 dd [2] 0a d7 [2] 1d dc [2] 06 92 [2] 3b }

  condition:
    any of them
}