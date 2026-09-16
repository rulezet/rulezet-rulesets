rule TTP_XOR_MULT_DOSStub_be92 {
  strings:
    $key_be92 = { ea fa [2] 9e e2 [2] d9 e0 [2] 9e f1 [2] d0 fd [2] dc f7 [2] cb fc [2] d0 b2 [2] ed }

  condition:
    any of them
}