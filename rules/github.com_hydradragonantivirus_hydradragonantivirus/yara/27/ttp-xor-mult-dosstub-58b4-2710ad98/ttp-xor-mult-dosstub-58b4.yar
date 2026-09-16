rule TTP_XOR_MULT_DOSStub_58b4 {
  strings:
    $key_58b4 = { 0c dc [2] 78 c4 [2] 3f c6 [2] 78 d7 [2] 36 db [2] 3a d1 [2] 2d da [2] 36 94 [2] 0b }

  condition:
    any of them
}