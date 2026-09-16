rule TTP_XOR_MULT_DOSStub_e699 {
  strings:
    $key_e699 = { b2 f1 [2] c6 e9 [2] 81 eb [2] c6 fa [2] 88 f6 [2] 84 fc [2] 93 f7 [2] 88 b9 [2] b5 }

  condition:
    any of them
}