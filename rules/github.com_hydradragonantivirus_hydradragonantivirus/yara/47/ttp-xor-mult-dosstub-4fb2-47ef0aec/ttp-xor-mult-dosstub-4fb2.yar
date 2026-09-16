rule TTP_XOR_MULT_DOSStub_4fb2 {
  strings:
    $key_4fb2 = { 1b da [2] 6f c2 [2] 28 c0 [2] 6f d1 [2] 21 dd [2] 2d d7 [2] 3a dc [2] 21 92 [2] 1c }

  condition:
    any of them
}