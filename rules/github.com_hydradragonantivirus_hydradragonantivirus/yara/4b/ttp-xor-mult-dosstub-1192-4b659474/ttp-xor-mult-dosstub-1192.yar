rule TTP_XOR_MULT_DOSStub_1192 {
  strings:
    $key_1192 = { 45 fa [2] 31 e2 [2] 76 e0 [2] 31 f1 [2] 7f fd [2] 73 f7 [2] 64 fc [2] 7f b2 [2] 42 }

  condition:
    any of them
}