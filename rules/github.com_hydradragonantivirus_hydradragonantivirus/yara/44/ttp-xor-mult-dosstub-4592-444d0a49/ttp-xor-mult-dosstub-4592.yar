rule TTP_XOR_MULT_DOSStub_4592 {
  strings:
    $key_4592 = { 11 fa [2] 65 e2 [2] 22 e0 [2] 65 f1 [2] 2b fd [2] 27 f7 [2] 30 fc [2] 2b b2 [2] 16 }

  condition:
    any of them
}