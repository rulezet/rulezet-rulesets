rule TTP_XOR_MULT_DOSStub_68b3 {
  strings:
    $key_68b3 = { 3c db [2] 48 c3 [2] 0f c1 [2] 48 d0 [2] 06 dc [2] 0a d6 [2] 1d dd [2] 06 93 [2] 3b }

  condition:
    any of them
}