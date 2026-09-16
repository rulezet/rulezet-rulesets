rule TTP_XOR_MULT_DOSStub_7ca8 {
  strings:
    $key_7ca8 = { 28 c0 [2] 5c d8 [2] 1b da [2] 5c cb [2] 12 c7 [2] 1e cd [2] 09 c6 [2] 12 88 [2] 2f }

  condition:
    any of them
}