rule TTP_XOR_MULT_DOSStub_4ca8 {
  strings:
    $key_4ca8 = { 18 c0 [2] 6c d8 [2] 2b da [2] 6c cb [2] 22 c7 [2] 2e cd [2] 39 c6 [2] 22 88 [2] 1f }

  condition:
    any of them
}