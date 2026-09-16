rule TTP_XOR_MULT_DOSStub_5d99 {
  strings:
    $key_5d99 = { 09 f1 [2] 7d e9 [2] 3a eb [2] 7d fa [2] 33 f6 [2] 3f fc [2] 28 f7 [2] 33 b9 [2] 0e }

  condition:
    any of them
}