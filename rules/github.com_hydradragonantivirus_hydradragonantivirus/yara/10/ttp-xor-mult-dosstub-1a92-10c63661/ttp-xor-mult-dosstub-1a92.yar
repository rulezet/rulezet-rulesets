rule TTP_XOR_MULT_DOSStub_1a92 {
  strings:
    $key_1a92 = { 4e fa [2] 3a e2 [2] 7d e0 [2] 3a f1 [2] 74 fd [2] 78 f7 [2] 6f fc [2] 74 b2 [2] 49 }

  condition:
    any of them
}