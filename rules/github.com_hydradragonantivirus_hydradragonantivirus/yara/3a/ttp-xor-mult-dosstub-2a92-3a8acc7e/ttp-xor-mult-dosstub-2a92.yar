rule TTP_XOR_MULT_DOSStub_2a92 {
  strings:
    $key_2a92 = { 7e fa [2] 0a e2 [2] 4d e0 [2] 0a f1 [2] 44 fd [2] 48 f7 [2] 5f fc [2] 44 b2 [2] 79 }

  condition:
    any of them
}