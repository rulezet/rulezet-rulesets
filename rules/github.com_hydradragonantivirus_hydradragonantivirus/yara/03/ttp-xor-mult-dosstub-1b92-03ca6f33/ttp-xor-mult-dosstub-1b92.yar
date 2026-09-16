rule TTP_XOR_MULT_DOSStub_1b92 {
  strings:
    $key_1b92 = { 4f fa [2] 3b e2 [2] 7c e0 [2] 3b f1 [2] 75 fd [2] 79 f7 [2] 6e fc [2] 75 b2 [2] 48 }

  condition:
    any of them
}