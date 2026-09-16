rule TTP_XOR_MULT_DOSStub_bb92 {
  strings:
    $key_bb92 = { ef fa [2] 9b e2 [2] dc e0 [2] 9b f1 [2] d5 fd [2] d9 f7 [2] ce fc [2] d5 b2 [2] e8 }

  condition:
    any of them
}