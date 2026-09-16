rule TTP_XOR_MULT_DOSStub_b292 {
  strings:
    $key_b292 = { e6 fa [2] 92 e2 [2] d5 e0 [2] 92 f1 [2] dc fd [2] d0 f7 [2] c7 fc [2] dc b2 [2] e1 }

  condition:
    any of them
}