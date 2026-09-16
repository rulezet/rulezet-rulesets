rule TTP_XOR_MULT_DOSStub_1fb4 {
  strings:
    $key_1fb4 = { 4b dc [2] 3f c4 [2] 78 c6 [2] 3f d7 [2] 71 db [2] 7d d1 [2] 6a da [2] 71 94 [2] 4c }

  condition:
    any of them
}