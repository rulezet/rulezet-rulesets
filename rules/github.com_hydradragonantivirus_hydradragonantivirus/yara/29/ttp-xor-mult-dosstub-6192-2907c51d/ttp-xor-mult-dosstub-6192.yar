rule TTP_XOR_MULT_DOSStub_6192 {
  strings:
    $key_6192 = { 35 fa [2] 41 e2 [2] 06 e0 [2] 41 f1 [2] 0f fd [2] 03 f7 [2] 14 fc [2] 0f b2 [2] 32 }

  condition:
    any of them
}