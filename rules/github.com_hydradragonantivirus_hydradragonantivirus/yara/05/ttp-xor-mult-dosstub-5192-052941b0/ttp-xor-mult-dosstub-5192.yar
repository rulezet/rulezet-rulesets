rule TTP_XOR_MULT_DOSStub_5192 {
  strings:
    $key_5192 = { 05 fa [2] 71 e2 [2] 36 e0 [2] 71 f1 [2] 3f fd [2] 33 f7 [2] 24 fc [2] 3f b2 [2] 02 }

  condition:
    any of them
}