rule TTP_XOR_MULT_DOSStub_6e92 {
  strings:
    $key_6e92 = { 3a fa [2] 4e e2 [2] 09 e0 [2] 4e f1 [2] 00 fd [2] 0c f7 [2] 1b fc [2] 00 b2 [2] 3d }

  condition:
    any of them
}