rule TTP_XOR_MULT_DOSStub_2192 {
  strings:
    $key_2192 = { 75 fa [2] 01 e2 [2] 46 e0 [2] 01 f1 [2] 4f fd [2] 43 f7 [2] 54 fc [2] 4f b2 [2] 72 }

  condition:
    any of them
}