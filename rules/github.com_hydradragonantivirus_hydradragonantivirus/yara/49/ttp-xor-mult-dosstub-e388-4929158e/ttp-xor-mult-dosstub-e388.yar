rule TTP_XOR_MULT_DOSStub_e388 {
  strings:
    $key_e388 = { b7 e0 [2] c3 f8 [2] 84 fa [2] c3 eb [2] 8d e7 [2] 81 ed [2] 96 e6 [2] 8d a8 [2] b0 }

  condition:
    any of them
}