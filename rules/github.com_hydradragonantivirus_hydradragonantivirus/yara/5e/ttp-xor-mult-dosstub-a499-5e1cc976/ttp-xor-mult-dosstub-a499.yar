rule TTP_XOR_MULT_DOSStub_a499 {
  strings:
    $key_a499 = { f0 f1 [2] 84 e9 [2] c3 eb [2] 84 fa [2] ca f6 [2] c6 fc [2] d1 f7 [2] ca b9 [2] f7 }

  condition:
    any of them
}