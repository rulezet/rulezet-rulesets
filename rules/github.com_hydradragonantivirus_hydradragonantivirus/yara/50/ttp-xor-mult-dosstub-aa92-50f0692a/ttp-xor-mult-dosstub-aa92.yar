rule TTP_XOR_MULT_DOSStub_aa92 {
  strings:
    $key_aa92 = { fe fa [2] 8a e2 [2] cd e0 [2] 8a f1 [2] c4 fd [2] c8 f7 [2] df fc [2] c4 b2 [2] f9 }

  condition:
    any of them
}