rule TTP_XOR_MULT_DOSStub_5fb4 {
  strings:
    $key_5fb4 = { 0b dc [2] 7f c4 [2] 38 c6 [2] 7f d7 [2] 31 db [2] 3d d1 [2] 2a da [2] 31 94 [2] 0c }

  condition:
    any of them
}