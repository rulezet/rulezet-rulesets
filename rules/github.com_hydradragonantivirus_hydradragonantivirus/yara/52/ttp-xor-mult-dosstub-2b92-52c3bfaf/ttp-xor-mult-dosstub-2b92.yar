rule TTP_XOR_MULT_DOSStub_2b92 {
  strings:
    $key_2b92 = { 7f fa [2] 0b e2 [2] 4c e0 [2] 0b f1 [2] 45 fd [2] 49 f7 [2] 5e fc [2] 45 b2 [2] 78 }

  condition:
    any of them
}