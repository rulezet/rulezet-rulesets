rule TTP_XOR_MULT_DOSStub_1ca8 {
  strings:
    $key_1ca8 = { 48 c0 [2] 3c d8 [2] 7b da [2] 3c cb [2] 72 c7 [2] 7e cd [2] 69 c6 [2] 72 88 [2] 4f }

  condition:
    any of them
}