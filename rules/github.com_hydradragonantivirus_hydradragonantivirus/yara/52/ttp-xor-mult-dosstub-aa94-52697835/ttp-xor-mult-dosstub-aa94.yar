rule TTP_XOR_MULT_DOSStub_aa94 {
  strings:
    $key_aa94 = { fe fc [2] 8a e4 [2] cd e6 [2] 8a f7 [2] c4 fb [2] c8 f1 [2] df fa [2] c4 b4 [2] f9 }

  condition:
    any of them
}