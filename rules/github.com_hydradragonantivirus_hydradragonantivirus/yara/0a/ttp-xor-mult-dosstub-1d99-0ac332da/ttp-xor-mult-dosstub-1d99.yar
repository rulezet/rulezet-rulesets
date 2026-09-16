rule TTP_XOR_MULT_DOSStub_1d99 {
  strings:
    $key_1d99 = { 49 f1 [2] 3d e9 [2] 7a eb [2] 3d fa [2] 73 f6 [2] 7f fc [2] 68 f7 [2] 73 b9 [2] 4e }

  condition:
    any of them
}