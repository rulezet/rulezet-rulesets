rule TTP_XOR_MULT_DOSStub_5b92 {
  strings:
    $key_5b92 = { 0f fa [2] 7b e2 [2] 3c e0 [2] 7b f1 [2] 35 fd [2] 39 f7 [2] 2e fc [2] 35 b2 [2] 08 }

  condition:
    any of them
}