rule TTP_XOR_MULT_DOSStub_6892 {
  strings:
    $key_6892 = { 3c fa [2] 48 e2 [2] 0f e0 [2] 48 f1 [2] 06 fd [2] 0a f7 [2] 1d fc [2] 06 b2 [2] 3b }

  condition:
    any of them
}