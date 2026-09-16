rule TTP_XOR_MULT_DOSStub_0799 {
  strings:
    $key_0799 = { 53 f1 [2] 27 e9 [2] 60 eb [2] 27 fa [2] 69 f6 [2] 65 fc [2] 72 f7 [2] 69 b9 [2] 54 }

  condition:
    any of them
}