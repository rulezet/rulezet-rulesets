rule TTP_XOR_MULT_DOSStub_b294 {
  strings:
    $key_b294 = { e6 fc [2] 92 e4 [2] d5 e6 [2] 92 f7 [2] dc fb [2] d0 f1 [2] c7 fa [2] dc b4 [2] e1 }

  condition:
    any of them
}