rule TTP_XOR_MULT_DOSStub_2092 {
  strings:
    $key_2092 = { 74 fa [2] 00 e2 [2] 47 e0 [2] 00 f1 [2] 4e fd [2] 42 f7 [2] 55 fc [2] 4e b2 [2] 73 }

  condition:
    any of them
}