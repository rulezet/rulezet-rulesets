rule TTP_XOR_MULT_DOSStub_b799 {
  strings:
    $key_b799 = { e3 f1 [2] 97 e9 [2] d0 eb [2] 97 fa [2] d9 f6 [2] d5 fc [2] c2 f7 [2] d9 b9 [2] e4 }

  condition:
    any of them
}