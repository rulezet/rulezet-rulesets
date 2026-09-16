rule TTP_XOR_MULT_DOSStub_4a99 {
  strings:
    $key_4a99 = { 1e f1 [2] 6a e9 [2] 2d eb [2] 6a fa [2] 24 f6 [2] 28 fc [2] 3f f7 [2] 24 b9 [2] 19 }

  condition:
    any of them
}