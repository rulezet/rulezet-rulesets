rule TTP_XOR_MULT_DOSStub_5d92 {
  strings:
    $key_5d92 = { 09 fa [2] 7d e2 [2] 3a e0 [2] 7d f1 [2] 33 fd [2] 3f f7 [2] 28 fc [2] 33 b2 [2] 0e }

  condition:
    any of them
}