rule TTP_XOR_MULT_DOSStub_e099 {
  strings:
    $key_e099 = { b4 f1 [2] c0 e9 [2] 87 eb [2] c0 fa [2] 8e f6 [2] 82 fc [2] 95 f7 [2] 8e b9 [2] b3 }

  condition:
    any of them
}