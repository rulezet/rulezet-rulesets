rule TTP_XOR_MULT_DOSStub_4d99 {
  strings:
    $key_4d99 = { 19 f1 [2] 6d e9 [2] 2a eb [2] 6d fa [2] 23 f6 [2] 2f fc [2] 38 f7 [2] 23 b9 [2] 1e }

  condition:
    any of them
}