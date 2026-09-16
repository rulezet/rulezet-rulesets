rule TTP_XOR_MULT_DOSStub_7a92 {
  strings:
    $key_7a92 = { 2e fa [2] 5a e2 [2] 1d e0 [2] 5a f1 [2] 14 fd [2] 18 f7 [2] 0f fc [2] 14 b2 [2] 29 }

  condition:
    any of them
}