rule TTP_XOR_MULT_DOSStub_6592 {
  strings:
    $key_6592 = { 31 fa [2] 45 e2 [2] 02 e0 [2] 45 f1 [2] 0b fd [2] 07 f7 [2] 10 fc [2] 0b b2 [2] 36 }

  condition:
    any of them
}