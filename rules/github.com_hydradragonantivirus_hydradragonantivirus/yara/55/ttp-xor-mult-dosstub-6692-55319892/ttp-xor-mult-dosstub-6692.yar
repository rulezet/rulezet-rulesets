rule TTP_XOR_MULT_DOSStub_6692 {
  strings:
    $key_6692 = { 32 fa [2] 46 e2 [2] 01 e0 [2] 46 f1 [2] 08 fd [2] 04 f7 [2] 13 fc [2] 08 b2 [2] 35 }

  condition:
    any of them
}