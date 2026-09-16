rule TTP_XOR_MULT_DOSStub_4b92 {
  strings:
    $key_4b92 = { 1f fa [2] 6b e2 [2] 2c e0 [2] 6b f1 [2] 25 fd [2] 29 f7 [2] 3e fc [2] 25 b2 [2] 18 }

  condition:
    any of them
}