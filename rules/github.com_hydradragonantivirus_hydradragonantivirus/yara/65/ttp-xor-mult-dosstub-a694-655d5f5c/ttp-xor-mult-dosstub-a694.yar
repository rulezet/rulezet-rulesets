rule TTP_XOR_MULT_DOSStub_a694 {
  strings:
    $key_a694 = { f2 fc [2] 86 e4 [2] c1 e6 [2] 86 f7 [2] c8 fb [2] c4 f1 [2] d3 fa [2] c8 b4 [2] f5 }

  condition:
    any of them
}