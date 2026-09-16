rule TTP_XOR_MULT_DOSStub_2792 {
  strings:
    $key_2792 = { 73 fa [2] 07 e2 [2] 40 e0 [2] 07 f1 [2] 49 fd [2] 45 f7 [2] 52 fc [2] 49 b2 [2] 74 }

  condition:
    any of them
}