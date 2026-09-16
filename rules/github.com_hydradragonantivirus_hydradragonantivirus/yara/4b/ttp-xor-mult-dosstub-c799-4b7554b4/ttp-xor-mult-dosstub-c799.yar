rule TTP_XOR_MULT_DOSStub_c799 {
  strings:
    $key_c799 = { 93 f1 [2] e7 e9 [2] a0 eb [2] e7 fa [2] a9 f6 [2] a5 fc [2] b2 f7 [2] a9 b9 [2] 94 }

  condition:
    any of them
}