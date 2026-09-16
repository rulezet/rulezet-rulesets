rule TTP_XOR_MULT_DOSStub_6ca8 {
  strings:
    $key_6ca8 = { 38 c0 [2] 4c d8 [2] 0b da [2] 4c cb [2] 02 c7 [2] 0e cd [2] 19 c6 [2] 02 88 [2] 3f }

  condition:
    any of them
}