rule TTP_XOR_MULT_DOSStub_2fb2 {
  strings:
    $key_2fb2 = { 7b da [2] 0f c2 [2] 48 c0 [2] 0f d1 [2] 41 dd [2] 4d d7 [2] 5a dc [2] 41 92 [2] 7c }

  condition:
    any of them
}