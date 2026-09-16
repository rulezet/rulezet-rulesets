rule TTP_XOR_MULT_DOSStub_3492 {
  strings:
    $key_3492 = { 60 fa [2] 14 e2 [2] 53 e0 [2] 14 f1 [2] 5a fd [2] 56 f7 [2] 41 fc [2] 5a b2 [2] 67 }

  condition:
    any of them
}