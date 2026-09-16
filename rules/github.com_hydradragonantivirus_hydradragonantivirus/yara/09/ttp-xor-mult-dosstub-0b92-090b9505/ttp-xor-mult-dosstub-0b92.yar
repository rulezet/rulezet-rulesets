rule TTP_XOR_MULT_DOSStub_0b92 {
  strings:
    $key_0b92 = { 5f fa [2] 2b e2 [2] 6c e0 [2] 2b f1 [2] 65 fd [2] 69 f7 [2] 7e fc [2] 65 b2 [2] 58 }

  condition:
    any of them
}