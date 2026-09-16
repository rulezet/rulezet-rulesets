rule TTP_XOR_MULT_DOSStub_2d99 {
  strings:
    $key_2d99 = { 79 f1 [2] 0d e9 [2] 4a eb [2] 0d fa [2] 43 f6 [2] 4f fc [2] 58 f7 [2] 43 b9 [2] 7e }

  condition:
    any of them
}