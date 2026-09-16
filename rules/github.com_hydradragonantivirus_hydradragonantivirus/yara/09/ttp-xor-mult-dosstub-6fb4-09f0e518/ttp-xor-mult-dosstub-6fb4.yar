rule TTP_XOR_MULT_DOSStub_6fb4 {
  strings:
    $key_6fb4 = { 3b dc [2] 4f c4 [2] 08 c6 [2] 4f d7 [2] 01 db [2] 0d d1 [2] 1a da [2] 01 94 [2] 3c }

  condition:
    any of them
}