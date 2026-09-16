rule TTP_XOR_MULT_DOSStub_5ca8 {
  strings:
    $key_5ca8 = { 08 c0 [2] 7c d8 [2] 3b da [2] 7c cb [2] 32 c7 [2] 3e cd [2] 29 c6 [2] 32 88 [2] 0f }

  condition:
    any of them
}