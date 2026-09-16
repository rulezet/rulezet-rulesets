rule TTP_XOR_MULT_DOSStub_1fb2 {
  strings:
    $key_1fb2 = { 4b da [2] 3f c2 [2] 78 c0 [2] 3f d1 [2] 71 dd [2] 7d d7 [2] 6a dc [2] 71 92 [2] 4c }

  condition:
    any of them
}