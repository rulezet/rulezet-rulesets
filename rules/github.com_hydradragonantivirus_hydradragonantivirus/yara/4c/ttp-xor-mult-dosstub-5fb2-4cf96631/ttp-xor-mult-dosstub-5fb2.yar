rule TTP_XOR_MULT_DOSStub_5fb2 {
  strings:
    $key_5fb2 = { 0b da [2] 7f c2 [2] 38 c0 [2] 7f d1 [2] 31 dd [2] 3d d7 [2] 2a dc [2] 31 92 [2] 0c }

  condition:
    any of them
}