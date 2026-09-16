rule TTP_XOR_MULT_DOSStub_2ca8 {
  strings:
    $key_2ca8 = { 78 c0 [2] 0c d8 [2] 4b da [2] 0c cb [2] 42 c7 [2] 4e cd [2] 59 c6 [2] 42 88 [2] 7f }

  condition:
    any of them
}