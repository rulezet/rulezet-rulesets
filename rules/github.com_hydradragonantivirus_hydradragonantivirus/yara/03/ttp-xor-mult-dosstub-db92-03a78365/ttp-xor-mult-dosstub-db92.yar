rule TTP_XOR_MULT_DOSStub_db92 {
  strings:
    $key_db92 = { 8f fa [2] fb e2 [2] bc e0 [2] fb f1 [2] b5 fd [2] b9 f7 [2] ae fc [2] b5 b2 [2] 88 }

  condition:
    any of them
}