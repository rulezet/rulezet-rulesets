rule TTP_XOR_MULT_DOSStub_7192 {
  strings:
    $key_7192 = { 25 fa [2] 51 e2 [2] 16 e0 [2] 51 f1 [2] 1f fd [2] 13 f7 [2] 04 fc [2] 1f b2 [2] 22 }

  condition:
    any of them
}