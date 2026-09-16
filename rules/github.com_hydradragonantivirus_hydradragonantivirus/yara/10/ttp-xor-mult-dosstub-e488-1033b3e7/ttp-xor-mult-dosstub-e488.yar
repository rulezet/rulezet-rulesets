rule TTP_XOR_MULT_DOSStub_e488 {
  strings:
    $key_e488 = { b0 e0 [2] c4 f8 [2] 83 fa [2] c4 eb [2] 8a e7 [2] 86 ed [2] 91 e6 [2] 8a a8 [2] b7 }

  condition:
    any of them
}