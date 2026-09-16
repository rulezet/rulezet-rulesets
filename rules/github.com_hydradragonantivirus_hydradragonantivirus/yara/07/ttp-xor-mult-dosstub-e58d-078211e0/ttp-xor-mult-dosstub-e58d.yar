rule TTP_XOR_MULT_DOSStub_e58d {
  strings:
    $key_e58d = { b1 e5 [2] c5 fd [2] 82 ff [2] c5 ee [2] 8b e2 [2] 87 e8 [2] 90 e3 [2] 8b ad [2] b6 }

  condition:
    any of them
}