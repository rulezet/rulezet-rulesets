rule TTP_XOR_MULT_DOSStub_3d99 {
  strings:
    $key_3d99 = { 69 f1 [2] 1d e9 [2] 5a eb [2] 1d fa [2] 53 f6 [2] 5f fc [2] 48 f7 [2] 53 b9 [2] 6e }

  condition:
    any of them
}